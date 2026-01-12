import fs from 'fs';

const filePath = 'extract.txt';

try {
	//extract data
	const data = fs.readFileSync(filePath, 'utf-8');

	// split string to items based on \n character
	const logsSplitted = data.split("\n");



	logsSplitted.forEach((event: string) => {
		console.log("======>: "+ event);
	});


} catch (error) {
	console.error('Error reading file:', error);
}
