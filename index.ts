import fs from 'fs';

const filePath = 'extract.txt';

try {
	//extract data
	const data = fs.readFileSync(filePath, 'utf-8');

	// split string to items based on \n character
	const splittingLogs = data.split("\n");

    const reFetchHostname : RegExp = /^(?:\S+\s+){3}(\S+)/;

    splittingLogs.forEach((item) => {
        const match = item.match(reFetchHostname)
        if (match) {
            // match[1] contient le hostname capturé
            console.log("Hostname :", match[1]);
        } else {
            // Pas de correspondance – la ligne n’est peut‑être pas au format syslog attendu
            console.log("Pas de hostname trouvé pour :", item);
        }
    });

} catch (error) {
	console.error('Error reading file:', error);
}
