import json

input_file = "mimikatz_sample.json"
output_file = "mimikatz_bulk.json"
index_name = "sample-attacks-credential-access"

with open(input_file) as f, open(output_file, "w") as out:
    for line in f:
        line = line.strip()
        if not line:
            continue
        action = {"index": {"_index": index_name}}
        out.write(json.dumps(action) + "\n")
        out.write(line + "\n")

print("Bulk file ready:", output_file)
