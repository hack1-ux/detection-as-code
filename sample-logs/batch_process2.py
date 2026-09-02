from evtx import PyEvtxParser
import json

files_to_index = {
    "exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx": "sample-attacks-execution",
    "DE_1102_security_log_cleared.evtx": "sample-attacks-defense-evasion",
    "bits_openvpn.evtx": "sample-attacks-c2",
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
