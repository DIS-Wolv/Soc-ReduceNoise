import fs from 'fs';


type HostnameLogMap = Map<string, string[]>;
const logsSegragatedOnHostname: HostnameLogMap = hostnameSegregationSyslog();

function hostnameSegregationSyslog(): HostnameLogMap{
    const logsToBeParsed = fs.readFileSync('./extract.txt', 'utf-8');
    const splittedLogsArray = logsToBeParsed.split("\n");

    try {
        const regexToFetchHostnameSyslog : RegExp = /^(?:\S+\s+){3}(\S+)/;
        const segregatedLogsArrayBasedOnHostname: HostnameLogMap = new Map();

        for (const log of splittedLogsArray){

            const match = log.match(regexToFetchHostnameSyslog);
            if (match && match.length > 1) {
                const hostname = match[1];
                const existing = 
                    segregatedLogsArrayBasedOnHostname.get(hostname!) ?? [];
                existing.push(log);
                
                segregatedLogsArrayBasedOnHostname.set(hostname!, existing);
            } 
        };

        return segregatedLogsArrayBasedOnHostname;
    } catch (error) {
        console.error('Error | couldn\'t segregate logs based on hostnames', error);
        throw error;
    }
}

console.log(logsSegragatedOnHostname)

