/**
 * SETUP
 */
import fs from 'fs';
import { stat } from "node:fs/promises";

/**
 * File & parsing constants
 */
const originalFilename: string = "dodi_center.json";
const processedFilename: string = "processed.json";

const syslogRegex =
  /^(\S+\s+\S+\s+\S+)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s+(.*)$/;

let originalFileSizeInKB: number;
let processedFileSizeInKB: number;

/**
 * CMDB custom field typing
 */
const CustomFieldsKeys = [
    // asset identification
    "hostname", "mac-address", "ip", "asset-type",
    "role", "os", "description",

    // asset location
    "environment", "physical", "cloud", "firewall-zone",
    "support-group", "physical-location", "exposure",

    // organisation
    "owner", "app-owner",
    "business-unit",

    // risk
    "criticality", "data-sensitivity", "likelyhood", "impact",
    "compliance", "confidence",

    // security
    "edr", "last-patch-date", "vuln-counts", "av",

    // role
    "technologies", "depends-on", "depends-of",
    "associated-apps", "asset-function"
] as const;

type CustomFieldKey = typeof CustomFieldsKeys[number];

type CmdbCustomField = {
    value: string | number;
};

type CmdbCustomFields = {
    [K in CustomFieldKey]?: CmdbCustomField;
};

/**
 * CMDB API response models
 */
type CmdbResponse = {
    total: number;
    rows: unknown[];
};

type CmdbRow = {
    id: number;
    name: string;
    custom_fields: CmdbCustomFields;
};

/**
 * Log processing structures
 */
type ProcessMessageEntry = {
    message: string;
    occurrences: string[];
};

// Optimized: Map for O(1) lookup of messages per process
type ProcessMessageMap = Map<string, ProcessMessageEntry>;

type HostEntry = {
    enrichment: Map<string, string | number>[]; // CmdbAsset
    processes: Map<string, ProcessMessageMap>;  // process -> messages map
};

type HostnameLogMap = Map<string, HostEntry>;

const sortedLogsOnHostnameAndProcess: HostnameLogMap = new Map();

/**
 * Serialized (JSON) models
 */
type SerializedCmdbAsset = Array<Record<string, string | number>>;

type SerializedProcessMessage = {
    message: string;
    occurrences: string[];
};

type SerializedProcesses = Record<string, SerializedProcessMessage[]>;

type SerializedHostEntry = {
    enrichment: SerializedCmdbAsset;
    processes: SerializedProcesses;
};

type SerializedHostnameLogs = Record<string, SerializedHostEntry>;

/**
 * Main thread
 */
async function main() {
    console.time("process")
    const cmdb = await fetchDataFromSnipeIT();
    if (!cmdb) throw new Error("No CMDB data");

    await gettingJSONFileSize(originalFilename);

    preprocessingLogs(cmdb);
    await gettingJSONFileSize(processedFilename);

    console.log(`A ${Math.floor(100 - (processedFileSizeInKB / originalFileSizeInKB) * 100)}% gain`)
    console.timeEnd("process")
}
main().catch(console.error);

/**
 * @returns result
 */
async function fetchDataFromSnipeIT(): Promise<CmdbResponse | undefined> {
    const url: string = process.env.URL!;
    const token: string = process.env.API!;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "Accept": "application/json",
                "Authorization": `Bearer ${token}`
            },
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`Response status: ${response.status}`);
        }

        const cmdbData = await response.json() as CmdbResponse;

        if (!cmdbData || !Array.isArray(cmdbData.rows)) {
            throw new Error("Invalid CMDB response shape");
        }

        return cmdbData;

    } catch (error) {
        console.error(error);
    } finally {
        clearTimeout(timeout);
    }
}

/**
 * @param _filename 
 */
async function gettingJSONFileSize(_filename: string): Promise<void> {
    const statResult = await stat(_filename);
    const fileSize = statResult.size / 1024;

    (_filename == originalFilename) ?
        originalFileSizeInKB = fileSize : processedFileSizeInKB = fileSize;

    console.info(`---> ${_filename} has a size of ${Math.floor(fileSize)} KB`);
}

/**
 * Preprocessor main function 
 * @returns sortedLogsOnHostnameAndProcess
*/
async function preprocessingLogs(_cmdb: CmdbResponse) {
    try {
        const logsToBeParsed = sortLogsToBeparsed();

        trimmingAndEnrichingLogs(_cmdb, logsToBeParsed);

        const serializedLogs = logSerialization();

        // readable
        //fs.writeFileSync(processedFilename, JSON.stringify(serializedLogs, null, 2), "utf-8");
        //compressed
        fs.writeFileSync(processedFilename, JSON.stringify(serializedLogs), "utf-8");


    } catch (error) {
        console.error(error);
        throw error;
    }
}

/**
 * triming and character cleanup is necessary
 * @returns logsToBeParsed: string[]
 */
function sortLogsToBeparsed(): string[] {
    const logsToBeParsed = fs.readFileSync(originalFilename, "utf-8")
        .split("\n")
        .map(line => line.trim())
        .filter(Boolean)
        .map(line => line.replace(/^"(.*)",?$/, "$1"));

    return logsToBeParsed;
}

/**
 * Main loop: parse logs, enrich with CMDB, record messages
 */
function trimmingAndEnrichingLogs(
    _cmdb_: CmdbResponse,
    _logsToBeParsed: string[]
) {
    for (let i = 0; i < _logsToBeParsed.length; i++) {
        const log = _logsToBeParsed[i];
        if (!log) continue;

        const match = syslogRegex.exec(log);
        if (!match) continue;

        const [ , timestampPart, hostname, process, pid, message ] = match;
        if (!timestampPart || !hostname || !process || !message) continue;

        let hostnameHolder = setParentHolderBasedOnhostname(_cmdb_, hostname);
        if (!hostnameHolder) continue;

        recordingLogMessageAndOccurences(hostnameHolder, process, message, timestampPart, pid);
    }
}

/**
 * Function either returns a hostname holder with log enrichment 
 * or nothing if hostname was already recorded
 */
function setParentHolderBasedOnhostname(
    _cmdb_: CmdbResponse,
    _hostname: string
): HostEntry | undefined {

    let sortLogsOnHostname = sortedLogsOnHostnameAndProcess.get(_hostname);

    if (!sortLogsOnHostname) {

        const cmdbRow = (_cmdb_.rows as CmdbRow[]).find(
            row => row.custom_fields.hostname?.value === _hostname
        );

        const enrichmentMap = new Map<string, string | number>();
        let likelyhood: number | null = null;
        let impact: number | null = null;
        let criticality: number | null = null;
        let dataSensitivity: number | null = null;

        if (cmdbRow) {
            for (let i = 0; i < CustomFieldsKeys.length; i++) {
                const key = CustomFieldsKeys[i];
                if (!key) continue;

                for (const k of CustomFieldsKeys) {
                    const entry = cmdbRow.custom_fields[k];
                    if (entry) enrichmentMap.set(k, entry.value);
                }

                switch (key) {
                    case "likelyhood":
                        likelyhood = Number(cmdbRow.custom_fields[key]!.value);
                        break;
                    case "impact":
                        impact = Number(cmdbRow.custom_fields[key]!.value);
                        break;
                    case "criticality":
                        criticality = Number(cmdbRow.custom_fields[key]!.value);
                        break;
                    case "data-sensitivity":
                        dataSensitivity = Number(cmdbRow.custom_fields[key]!.value);
                        break;
                }
            }
        }

        const ImpactScore = dataSensitivity! + impact! + criticality!;
        const RiskScore = Math.round((ImpactScore * likelyhood! / 27) * 10);

        enrichmentMap.set("risk-score", RiskScore);
        enrichmentMap.set("eol-date", (cmdbRow as any).asset_eol_date.date);

        // Initialize the host entry for this hostname:
        // - `enrichment`: wrap the CMDB data (`enrichmentMap`) in an array if it has any fields, otherwise an empty array
        // - `processes`: create an empty Map to store processes and their associated log messages
        sortLogsOnHostname = {
            enrichment: enrichmentMap.size > 0 ? [enrichmentMap] : [],
            processes: new Map<string, ProcessMessageMap>()
        };

        sortedLogsOnHostnameAndProcess.set(_hostname, sortLogsOnHostname);
    }

    return sortLogsOnHostname;
}

/**
 * Append to hostname holder the process holder if it was not recorded yet
 * and message structure.
 * Then append message if it does not exist yet + the occurences represented
 * as timestamps
 */
function recordingLogMessageAndOccurences(
    _hostnameHolder: HostEntry,
    _process: string,
    _logMessage: string,
    timestamp: string,
    pid?: string
) {
    let processMap = _hostnameHolder.processes.get(_process);
    if (!processMap) {
        processMap = new Map();
        _hostnameHolder.processes.set(_process, processMap);
    }

    let entry = processMap.get(_logMessage);
    if (!entry) {
        entry = { message: _logMessage, occurrences: [] };
        processMap.set(_logMessage, entry);
    }

    const datePart = pid ? `${timestamp} [${pid}]` : timestamp;
    entry.occurrences.push(datePart);
}

/**
 * Serialize logs or JSON file
 */
function logSerialization(): SerializedHostnameLogs {
    const outputObj: SerializedHostnameLogs = {};

    for (const [hostname, processEntry] of sortedLogsOnHostnameAndProcess) {

        outputObj[hostname] = {
            enrichment: processEntry.enrichment.map(m => Object.fromEntries(m)),
            processes: {}
        };

        for (const [process, messageMap] of processEntry.processes) {
            outputObj[hostname].processes[process] =
                Array.from(messageMap.values()).map(entry => ({
                    message: entry.message,
                    occurrences: entry.occurrences
                }));
        }
    }
    return outputObj;
}
