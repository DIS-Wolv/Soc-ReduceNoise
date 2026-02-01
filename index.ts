/**
 * SETUP
 */
import fs from 'fs';
import { stat } from "node:fs/promises";

// structure of record holder & fetch data
type CmdbAsset = [Map<string, string|number>];
type HostEntry = {
    enrichment: CmdbAsset;
    processes: Map<string, Map<string, string[]>>;
};
type HostnameLogMap = Map<string, HostEntry>;
const sortedLogsOnHostnameAndProcess: HostnameLogMap = new Map();

type CmdbResponse = {
  total: number;                                                                // for page collection
  rows: unknown[];
};

const originalFilename: string = "messages.json";
const processedFilename:string = "processed.json";
const regexToFetchHostnameSyslog = /^\S+\s+\S+\s+\S+\s+(\S+)/;
const regexToFetchProcessSyslog = /^\S+\s+\S+\s+\S+\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:/;

let originalFileSizeInKB: number;
let processedFileSizeInKB: number;

/**
 * Calling functions
 */

async function main() {
    const result = await getData();
    // await gettingJSONFileSize(originalFilename);
    hostnameSegregationSyslog(result!);
    // await gettingJSONFileSize(processedFilename);
}

main().catch(console.error);

/**
 * fetch data on snipe it API
 * 
 * @returns result
 */
async function getData(): Promise<CmdbResponse | undefined> {
    const url: string = process.env.URL!;
    const token: string = process.env.API!;
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    try{

        const response = await fetch(url,{
            method: "GET",
            headers:{
                "Accept": "application/json",
                "Authorization": `Bearer ${token}`
            },
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`Response status: ${response.status}`);
        }
        
        const result = await response.json() as CmdbResponse;

        if (!result || !Array.isArray(result.rows)) {
            throw new Error("Invalid CMDB response shape");
        }
        
        return result;

    }catch(error){
        console.error(error);
    } finally {
        clearTimeout(timeout);
    }

}


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
async function hostnameSegregationSyslog(_result: CmdbResponse){
    try {
        
        const logsToBeParsed = fs.readFileSync(originalFilename, "utf-8")       
            .split("\n")
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => line.replace(/^"(.*)",?$/, "$1"));

            for (let i = 0; i< logsToBeParsed.length; i++) {

                const log = logsToBeParsed[i];
                if (!log || !logsToBeParsed[i]) continue; 
                
                const hostnameMatch = log.match(regexToFetchHostnameSyslog);        
                const processMatch = log.match(regexToFetchProcessSyslog);
                
                if (!hostnameMatch || !hostnameMatch[1] ||                          // if not matching rg, start ew iteration 
                    !processMatch || !processMatch[1]) continue;                    // of the loop | safety check
                    
                    const hostname = hostnameMatch[1];                                  
                    const process  = processMatch[1];
                    
                    const separatorIndex = log.indexOf(": ");
                    if (separatorIndex === -1) continue;
                    
                    const messageKey = log.slice(separatorIndex + 2);                   // message body (deduplication key)
                    console.log(messageKey)
                    /*
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
            */
        }
        
        //fs.writeFileSync(processedFilename, JSON                                // wrtie to processedFilename
        //    .stringify(outputObj, null, 2), "utf-8");

    } catch (error) {
        console.error(error);
        throw error;
    }
}
