/**
 * SETUP
 */
import fs from 'fs';
import { stat } from "node:fs/promises";

type CmdbAsset = Map<string, string | number>[];                                  // cmdb data
type ProcessMessageEntry = {
    message: string;
    occurrences: string[];
};

type HostEntry = {
    enrichment: CmdbAsset;
    processes: Map<string, ProcessMessageEntry[]>;
};
type HostnameLogMap = Map<string, HostEntry>;                                   // hostname, HostEntry
const sortedLogsOnHostnameAndProcess: HostnameLogMap = new Map();

type CmdbResponse = {
    total: number;                                                                // API response handler, total being for pagination
    rows: unknown[];
};

const originalFilename: string = "dodi_center.json";
const processedFilename: string = "processed.json";
const regexToFetchHostnameSyslog = /^\S+\s+\S+\s+\S+\s+(\S+)/;
const regexToFetchProcessSyslog = /^\S+\s+\S+\s+\S+\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:/;

let originalFileSizeInKB: number;
let processedFileSizeInKB: number;

const CustomFieldsKeys: string[] = [
    //asset identification
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
    "technologies", "depends-on", "depends-of", "associated-apps", "asset-function"
] as const;

type CustomFieldKey = typeof CustomFieldsKeys[number];
// ensure the process array exists, then push.

type CmdbCustomField = {
    value: string | number;
};

type CmdbCustomFields = {
    [K in CustomFieldKey]?: CmdbCustomField;
};


/**
 * Calling functions
 */
async function main() {
    //console.time()
    const cmdb = await getData();
    await gettingJSONFileSize(originalFilename);
    hostnameSegregationSyslog(cmdb!);
    await gettingJSONFileSize(processedFilename);
    console.log(`A ${Math.floor(100 - (processedFileSizeInKB / originalFileSizeInKB) * 100)}% gain`)
    //console.timeEnd()
}
main().catch(console.error);



/**
 * fetch data on snipe it API
 * @returns result
 */
async function getData(): Promise<CmdbResponse | undefined> {
    const url: string = process.env.URL!;
    const token: string = process.env.API!;

    const controller = new AbortController();                                   // kill switch
    const timeout = setTimeout(() => controller.abort(), 5000);                 // function to kill process if no response upon signal

    try {

        const response = await fetch(url, {
            method: "GET",
            headers: {
                "Accept": "application/json",
                "Authorization": `Bearer ${token}`
            },
            signal: controller.signal                                           // signal for kill switch
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
        clearTimeout(timeout);                                                  // clear timer
    }

}


/**
 * getting file size - self explenatory
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
 * Preprocessor function 
 * @returns sortedLogsOnHostnameAndProcess
*/
async function hostnameSegregationSyslog(_cmdb: CmdbResponse) {
    console.time("process")
    try {

        const logsToBeParsed = fs.readFileSync(originalFilename, "utf-8")       // parsing json
            .split("\n")
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => line.replace(/^"(.*)",?$/, "$1"));

        for (let i = 0; i < logsToBeParsed.length; i++) {

            const log = logsToBeParsed[i];
            if (!log || !logsToBeParsed[i]) continue;

            const hostnameMatch = log.match(regexToFetchHostnameSyslog);
            const processMatch = log.match(regexToFetchProcessSyslog);

            if (!hostnameMatch || !hostnameMatch[1] ||                          // if not matching rg, continue to new iteration 
                !processMatch || !processMatch[1]) continue;

            const hostname = hostnameMatch[1];
            const process = processMatch[1];

            const separatorIndex = log.indexOf(": ");
            if (separatorIndex === -1) continue;

            const messageKey = log.slice(separatorIndex + 2);               // message body (deduplication key)
            let sortLog = sortedLogsOnHostnameAndProcess.get(hostname);     // For each log, ensure the hostname map exists, 

            if (!sortLog) {

                type CmdbRow = {
                    id: number;
                    name: string;
                    custom_fields: CmdbCustomFields;
                };

                const cmdbRow = (_cmdb.rows as CmdbRow[]).find(
                    row => row.custom_fields.hostname?.value === hostname
                );

                const enrichmentMap = new Map<string, string | number>();
                let likelyhood: number | null = null;
                let impact: number | null = null;
                let criticality: number | null = null;
                let dataSensitivity: number | null = null;

                if (cmdbRow) {

                    for (let i = 0; i < CustomFieldsKeys.length; i++) {
                        const key = CustomFieldsKeys[i];
                        if (!key) continue;  // narrow key from string | undefined → string

                        for (const k of CustomFieldsKeys) {
                            const entry = cmdbRow.custom_fields[k];
                            if (entry) {
                                enrichmentMap.set(k, entry.value);
                            }
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

                const ImpactScore = dataSensitivity! + impact! + criticality!
                const Risk = ImpactScore * likelyhood!;
                const RiskOutOf10 = Math.round((Risk / 27) * 10)

                enrichmentMap.set("risk-score", RiskOutOf10);

                enrichmentMap.set("eol-date", cmdbRow.asset_eol_date.date!);



                sortLog = {
                    enrichment: enrichmentMap.size > 0 ? [enrichmentMap] : [],
                    processes: new Map<string, ProcessMessageEntry[]>()
                };


                sortedLogsOnHostnameAndProcess.set(hostname, sortLog);      // returns HostnameLogMap type
            }


            let messageEntries = sortLog.processes.get(process);
            if (!messageEntries) {
                messageEntries = [];
                sortLog.processes.set(process, messageEntries);
            }


            let entry = messageEntries.find(e => e.message === messageKey);
            if (!entry) {
                entry = { message: messageKey, occurrences: [] };
                messageEntries.push(entry);
            }

            const timestamp = log.split(" ", 4).slice(0, 3).join(" ");      // process and push date 
            const pidMatch = log.match(/\[(\d+)\]/);
            const pid = pidMatch ? pidMatch[1] : undefined;
            const datePart = pid
                ? `${timestamp} [${pid}]`
                : timestamp;

            entry.occurrences.push(datePart);

        }



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

        const outputObj: SerializedHostnameLogs = {};

        for (const [hostname, processEntry] of sortedLogsOnHostnameAndProcess) {

            outputObj[hostname] = {
                enrichment: processEntry.enrichment.map(m => Object.fromEntries(m)),
                processes: {}
            };

            for (const [process, messageEntries] of processEntry.processes) {

                outputObj[hostname].processes[process] =
                    messageEntries.map(entry => ({
                        message: entry.message,
                        occurrences: entry.occurrences
                    }));
            }
        }



        fs.writeFileSync(processedFilename, JSON                                // write to JSON file
            .stringify(outputObj, null, 2), "utf-8");

    } catch (error) {
        console.error(error);
        throw error;
    }
}
