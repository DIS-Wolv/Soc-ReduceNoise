/**
 * SETUP
 */
import fs from 'fs';
import { stat } from "node:fs/promises";

const originalFilename: string = "original.json";
const processedFilename:string = "processed.json";
const regexToFetchHostnameSyslog = /^\S+\s+\S+\s+\S+\s+(\S+)/;
const regexToFetchProcessSyslog = /^\S+\s+\S+\s+\S+\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:/;

let originalFileSizeInKB: number;
let processedFileSizeInKB: number;

// structure of record holder
type HostnameLogMap = Map<string, Map<string, string[]>>;
const sortedLogsOnHostnameAndProcess: HostnameLogMap = new Map();


/**
 * getting file size 
 * @param _filename 
 */
async function gettingJSONFileSize(_filename: string): Promise<void>{
    const statResult = await stat(_filename);
    const fileSize = statResult.size / 1024;

    (_filename == "original.json") ? 
        originalFileSizeInKB    =   fileSize:
        processedFileSizeInKB   =   fileSize;

    console.info(`---> ${_filename} has a size of ${Math.floor(fileSize)} KB`);
}


/**
 * Preprocessor function 
 * @returns sortedLogsOnHostnameAndProcess
*/
function hostnameSegregationSyslog(){

    try {
        
        const logsToBeParsed = fs.readFileSync(originalFilename, "utf-8")       
            .split("\n")
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => line.replace(/^"(.*)",?$/, "$1"));

        for (const log of logsToBeParsed) {

            const hostnameMatch = log.match(regexToFetchHostnameSyslog);        
            const processMatch = log.match(regexToFetchProcessSyslog);

            if (!hostnameMatch || !hostnameMatch[1] ||                          // if not matching rg, start ew iteration 
                !processMatch || !processMatch[1]) continue;                    // of the loop | safety check

            const hostname = hostnameMatch[1];                                  
            const process  = processMatch[1];

            let processMap = sortedLogsOnHostnameAndProcess.get(hostname)       // For each log, ensure the hostname map exists, 
            if (!processMap) {                                                  // ensure the process array exists, then push.
                processMap = new Map<string, string[]>();                       // returns HostnameLogMap type
                sortedLogsOnHostnameAndProcess.set(hostname, processMap);
            }

            let processLogs = processMap.get(process);
            if (!processLogs) {
                processLogs = [];
                processMap.set(process, processLogs);
            }

            processLogs.push(log);
            
        }

        const outputObj: Record<string, Record<string, string[]>> = {};         // Convert the nested Map structure (hostname → process → logs) 
        for (const [hostname, procMap] of sortedLogsOnHostnameAndProcess) {     // into a plain object suitable for JSON serialization.
            outputObj[hostname] = {};                                           // sets top level JSON key
            for (const [proc, logs] of procMap) {
                outputObj[hostname][proc] = logs;                               // sets sub structure savec in above one
            }
        }


        fs.writeFileSync(processedFilename, JSON                                // wrtie to processedFilename
            .stringify(outputObj, null, 2), "utf-8");

    } catch (error) {
        console.error("Error | couldn't segregate logs based on hostnames", error);
        throw error;
    }
}

/**
 * Calling functions
 */

gettingJSONFileSize(originalFilename);

hostnameSegregationSyslog();