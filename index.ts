/**
 * SETUP
 */
import fs from 'fs';
import { stat } from "node:fs/promises";

const originalFilename: string = "rooty.json";
const processedFilename:string = "rooty_processed.json";
const regexToFetchHostnameSyslog = /^\S+\s+\S+\s+\S+\s+(\S+)/;
const regexToFetchProcessSyslog = /^\S+\s+\S+\s+\S+\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:/;

let originalFileSizeInKB: number;
let processedFileSizeInKB: number;

// structure of record holder
type HostnameLogMap =   Map<string, Map<string, Map<string, string[]>>>;
const sortedLogsOnHostnameAndProcess: HostnameLogMap = new Map();


/**
 * getting file size 
 * @param _filename 
 */
async function gettingJSONFileSize(_filename: string): Promise<void>{
    const statResult = await stat(_filename);
    console.log(_filename)
    const fileSize = statResult.size / 1024;

    (_filename == "original.json") ? 
        originalFileSizeInKB    =   fileSize:
        processedFileSizeInKB   =   fileSize;

    await console.log(typeof(processedFileSizeInKB) )
    await console.log(typeof(originalFileSizeInKB) )

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

            const separatorIndex = log.indexOf(": ");
            if (separatorIndex === -1) continue;

            const messageKey = log.slice(separatorIndex + 2);                   // message body (deduplication key)
  
            let processMap = sortedLogsOnHostnameAndProcess.get(hostname)       // For each log, ensure the hostname map exists, 
            if (!processMap) {                                                  // ensure the process array exists, then push.
                processMap = new Map<string, Map<string, string[]>>();          // returns HostnameLogMap type
                sortedLogsOnHostnameAndProcess.set(hostname, processMap);
            }

            let messageMap = processMap.get(process);                           // reiterate process for process
            if (!messageMap) {                                  
                messageMap = new Map<string, string[]>();
                processMap.set(process, messageMap);                            // it adds the message
            }

            let occurrences = messageMap.get(messageKey);                       // check the log message
            if (!occurrences) {
                occurrences = [];
                messageMap.set(messageKey, occurrences);                        
            }

            const timestamp = log.split(" ", 4).slice(0, 3).join(" ");          // process and push date 
            const pidMatch = log.match(/\[(\d+)\]/);
            const pid = pidMatch ? pidMatch[1] : undefined;
            const datePart = pid
                ? `${timestamp} [${pid}]`
                : timestamp;

            occurrences.push(datePart);

        }

        const outputObj: Record<string, Record<string, Record<string, string[]>>> = {};         // Convert the nested Map structure (hostname → process → logs) 
        for (const [hostname, processMap] of sortedLogsOnHostnameAndProcess) {     // into a plain object suitable for JSON serialization.
            outputObj[hostname] = {};                                           // sets top level JSON key
            
            for (const [process, messageMap] of processMap) {
                outputObj[hostname][process] = {};                               // sets sub structure savec in above one
                
                for (const [message, dates] of messageMap) {
                    outputObj[hostname][process][message] = dates;
                }
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

async function main() {
    await gettingJSONFileSize(originalFilename);
    hostnameSegregationSyslog();
    await gettingJSONFileSize(processedFilename);
   //await console.log(Math.floor((processedFileSizeInKB / originalFileSizeInKB)*100))
}

main().catch(console.error);

/**
 * Normalize timestamps → store as ISO or epoch for easier sorting/comparison.

Optional PID metadata → keep PID separate from date string for flexibility.

Message normalization → replace volatile data (IPs, UUIDs, user IDs) for better deduplication.

Async I/O → use fs.promises for reading/writing large files to avoid blocking.

Memory optimization → consider streaming large files instead of loading all logs at once.

Add counts / firstSeen / lastSeen → easier analytics without parsing arrays.

Configurable keys → allow toggling PID inclusion or message normalization.
 */