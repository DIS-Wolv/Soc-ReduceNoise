import fs from 'fs';
import { stat } from "node:fs/promises";

/**
 * filenames
 */

const originalFilename: string = "original.json";
const processedFilename: string = "processed.json";

/**
 * Getting and print file size
 */

let originalFileSizeInKB: number;
let processedFileSizeInKB: number;

async function gettingJSONFileSize(_filename: string): Promise<void>{
    const statResult = await stat(_filename);
    const fileSize: number = statResult.size / 1024;

    (_filename == "original.json") ? 
        originalFileSizeInKB    =   fileSize:
        processedFileSizeInKB   =   fileSize;

    console.info(`---> ${_filename} has a size of ${Math.floor(fileSize)} KB`);
}

gettingJSONFileSize(originalFilename);


/**
 * Regexes for hosntame and processes
 * HostnameLogMap - creates an map type, containing a string (key - hostname), 
 * holding itself a value of map of a string (key - process) and string array (value - log)
 * segregatedLogsArrayBasedOnHostname is Map holding HostnameLogMap type
 */

const regexToFetchHostnameSyslog = /^\S+\s+\S+\s+\S+\s+(\S+)/;
const regexToFetchProcessSyslog = /^\S+\s+\S+\s+\S+\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:/;
type HostnameLogMap = Map<string, Map<string, string[]>>;
const segregatedLogsArrayBasedOnHostname: HostnameLogMap = new Map();


/**
 * 1. extract the logs and cut them off based on \n 
 *      trim() to remove whitespaces
 *      boolean to filter empty strings
 *      remove extra characters that may exist
 * 
 * 2. for each log, check a match with hostname, if so store to doesHosntameExists
 * 3. if no, create new array witch matching new hostname
 * 4. push log to array
 * 
 * @returns segregatedLogsArrayBasedOnHostname
*/

hostnameSegregationSyslog();

function hostnameSegregationSyslog(): void{

    try {
        
        // 1.
        const logsToBeParsed = fs.readFileSync(originalFilename, "utf-8")
            .split("\n")
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => line.replace(/^"(.*)",?$/, "$1"));

        // 
        for (const log of logsToBeParsed) {
            const hostnameMatch = log.match(regexToFetchHostnameSyslog);
            const processMatch = log.match(regexToFetchProcessSyslog);

            // 
            if (!hostnameMatch || !hostnameMatch[1]) continue;
            if (!processMatch || !processMatch[1]) continue;

            const hostname = hostnameMatch[1];
            const process = processMatch[1];

            // 
            let processMap = segregatedLogsArrayBasedOnHostname.get(hostname);
            if (!processMap) {
                processMap = new Map<string, string[]>();
                segregatedLogsArrayBasedOnHostname.set(hostname, processMap);
            }

            // 
            let processLogs = processMap.get(process);
            if (!processLogs) {
                processLogs = [];
                processMap.set(process, processLogs);
            }

            // 
            processLogs.push(log);
        }

        const outputObj: Record<string, Record<string, string[]>> = {};
        for (const [hostname, procMap] of segregatedLogsArrayBasedOnHostname) {
            outputObj[hostname] = {};
            for (const [proc, logs] of procMap) {
                outputObj[hostname][proc] = logs;
            }
        }

        // write processed JSON
        fs.writeFileSync(processedFilename, JSON.stringify(outputObj, null, 2), "utf-8");

    } catch (error) {
        console.error("Error | couldn't segregate logs based on hostnames", error);
        throw error;
    }
}