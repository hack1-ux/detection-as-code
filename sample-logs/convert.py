from evtx import PyEvtxParser
import json

parser = PyEvtxParser("CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx")

with open("mimikatz_sample.json", "w") as f:
    for record in parser.records_json():
        f.write(record["data"] + "\n")

print("Done converting.")
