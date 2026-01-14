import fs from 'fs';

const filePath = './extract.txt';

try {
	const logsToBeParsed = fs.readFileSync(filePath, 'utf-8');

	const splittedLogsArray = logsToBeParsed.split("\n");

    const regexToFetchHostnameSyslog : RegExp = /^(?:\S+\s+){3}(\S+)/;

    type HostnameLogMap = Map<string, string[]>;
    const segregatedLogsArrayBasedOnHostname: HostnameLogMap = new Map();

    console.time()

    for (const log of splittedLogsArray){
        const match = log.match(regexToFetchHostnameSyslog)

        if (match && match.length > 1) {
            const hostname = match[1];
            const existing = segregatedLogsArrayBasedOnHostname.get(hostname!) ?? [];
            existing.push(log);
            
            segregatedLogsArrayBasedOnHostname.set(hostname!, existing);
        } 
    };

    console.log(segregatedLogsArrayBasedOnHostname)

    console.timeEnd();

} catch (error) {
	console.error('Error reading file:', error);
}
