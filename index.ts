import fs from 'fs';

/**
 * HostnameLogMap - creates an array type, containing a string (index) and array
 */
type HostnameLogMap = Map<string, string[]>;

/**
 * regexToFetchHostnameSyslog           -   the rg to get log hostname | syslog format
 * segregatedLogsArrayBasedOnHostname   -   the processed logs map contained in below map
 * logsSegragatedOnHostname             -   will store all the logs
 */
const regexToFetchHostnameSyslog : RegExp = /^(?:\S+\s+){3}(\S+)/;
const segregatedLogsArrayBasedOnHostname: HostnameLogMap = new Map();
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

    const logsToBeParsed = fs.readFileSync('./extract.txt', 'utf-8');
    const splittedLogsArray = logsToBeParsed.split("\n");
        
    try {
        for (const log of splittedLogsArray){

            const match = log.match(regexToFetchHostnameSyslog);
            if (match && match.length > 1) {
                const hostname = match[1];
                const doesHostnameExists = segregatedLogsArrayBasedOnHostname.get(hostname!) ?? [];
                doesHostnameExists.push(log);
                
                segregatedLogsArrayBasedOnHostname.set(hostname!, doesHostnameExists);
            } 
        };

        return segregatedLogsArrayBasedOnHostname;
    
    } catch (error) {
        console.error('Error | couldn\'t segregate logs based on hostnames', error);
        throw error;
    }
}

console.log(logsSegragatedOnHostname)

