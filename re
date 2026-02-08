#!/usr/bin/env python3
import json, re

INPUT_FILE = "processed.json"
OUTPUT_FILE = "output.json"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    for host_data in data.values():

        processes = host_data.get("processes", {})

        # Base sans enrichment ni processes
        base_data = {}
        for key, value in host_data.items():
            if key not in ("enrichment", "processes"):
                base_data[key] = value

        # Gestion enrichment (liste OU dict)
        enrichment = host_data.get("enrichment", {})
        if isinstance(enrichment, list) and enrichment:
            enrichment = enrichment[0]
        elif not isinstance(enrichment, dict):
            enrichment = {}

        # Enrichment à la racine
        base_data.update(enrichment)

        for process_name, events in processes.items():
            for event in events:
                for ts in event.get("occurrences", []):
                    record = dict(base_data)

                    m = re.match(r'^(.+?)\s+\[(\d+)\]$', ts)
                    if m:
                        ts = m.group(1)
                        pid = m.group(2)
                    
                    record.update({
                        "Timestamp": ts,
                        "PID": pid,
                        "message": event.get("message"),
                        "process_name": process_name
                    })

                    out.write(json.dumps(record, ensure_ascii=False) + "\n")
