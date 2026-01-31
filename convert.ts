import { readFile, writeFile } from "fs/promises";

const inputFile = "rooty.txt";
const outputFile = "rooty.json";

// 1. Read the TXT file
const content = await readFile(inputFile, "utf8");

// 2. Split into lines
const result = content
  .split("\n")
  .map(line => line.trim())
  .filter(Boolean);

// 3. Write JSON file
await writeFile(
  outputFile,
  JSON.stringify(result, null, 2),
  "utf8"
);

console.log("TXT file converted to JSON successfully");
