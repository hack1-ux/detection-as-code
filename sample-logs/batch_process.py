from evtx import PyEvtxParser
import json
import sys

files_to_index = {
    "discovery_bloodhound.evtx": "sample-attacks-discovery",
    "persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx": "sample-attacks-persistence",
    "LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx": "sample-attacks-lateral-movement",
}

for filename, index_name in files_to_index.items():
    bulk_filename = filename.replace(".evtx", "_bulk.json")
    count = 0
    try:
        parser = PyEvtxParser(filename)
        with open(bulk_filename, "w") as out:
            for record in parser.records_json():
                action = {"index": {"_index": index_name}}
                out.write(json.dumps(action) + "\n")
                out.write(record["data"] + "\n")
                count += 1
        print(f"{filename}: {count} events -> {bulk_filename} (index: {index_name})")
    except Exception as e:
        print(f"ERROR processing {filename}: {e}")
