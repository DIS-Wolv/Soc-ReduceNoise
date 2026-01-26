import fs from 'fs';

/**
 * HostnameLogMap - creates an array type, containing a string (index) and array
 */
type HostnameLogMap = Map<string, Map<string, string[]>>;

/**
 * regexToFetchHostnameSyslog           -   the rg to get log hostname ; syslog format
 * segregatedLogsArrayBasedOnHostname   -   the processed logs map contained in below map
 * regexToFetchProcessSyslog            -   the rg to get log process ; syslog format
 * logsSegragatedOnHostname             -   will store all the logs
 */
const regexToFetchHostnameSyslog : RegExp = /^(?:\S+\s+){3}(\S+)/;
const segregatedLogsArrayBasedOnHostname: HostnameLogMap = new Map();
const regexToFetchProcessSyslog : RegExp = /^\S+\s+\S+\s+\S+\s+\S+\s+([^\s\[:]+)(?:\[\d+\])?:/;
const logsSegragatedOnHostname: HostnameLogMap = hostnameSegregationSyslog();

/**
 * 1. extract the logs and cut them off based on \n
 * 2. for each log, check a match with hostname, if so store to doesHosntameExists
 * 3. if no, create new array witch matching new hostname
 * 4. push log to array
 * 
 * @returns segregatedLogsArrayBasedOnHostname
 */
function hostnameSegregationSyslog(): HostnameLogMap{

    const logsToBeParsed = fs.readFileSync('./og.txt', 'utf-8');
    const splittedLogsArray = logsToBeParsed.split("\n");
        
    try {
        for (const log of splittedLogsArray){
            
            if (!log.trim()) continue;

            const hostnameMatch = log.match(regexToFetchHostnameSyslog);
            const processMatch = log.match(regexToFetchProcessSyslog);

            if ( hostnameMatch && hostnameMatch.length > 1 &&
                processMatch && processMatch.length > 1
            ) {
                const hostname = hostnameMatch[1];
                const process = processMatch[1];

                // 1️⃣ Get or create process map for hostname
                const processMap = segregatedLogsArrayBasedOnHostname.get(hostname!) ??
                new Map<string, string[]>();

                // 2️⃣ Get or create log array for process
                const processLogs = processMap.get(process!) ?? [];

                // 3️⃣ Push log
                processLogs.push(log);

                // 4️⃣ Persist back into maps
                processMap.set(process!, processLogs);
                segregatedLogsArrayBasedOnHostname.set(hostname!, processMap);
            }

        };

        return segregatedLogsArrayBasedOnHostname;
    
    } catch (error) {
        console.error('Error | couldn\'t segregate logs based on hostnames', error);
        throw error;
    }
}

console.log(logsSegragatedOnHostname)

