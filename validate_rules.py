import sys
import glob
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend

rule_files = sorted(glob.glob("rules/**/*.yml", recursive=True))

if not rule_files:
    print("No rule files found under rules/")
    sys.exit(1)

backend = OpensearchLuceneBackend()
failed = []

for path in rule_files:
    try:
        with open(path) as f:
            rule_yaml = f.read()
        rules = SigmaCollection.from_yaml(rule_yaml)
        queries = backend.convert(rules)
        query_str = queries[0] if queries else "(no query generated)"
        print(f"OK   {path}")
        print(f"     -> {query_str}")
    except Exception as e:
        print(f"FAIL {path}")
        print(f"     -> {e}")
        failed.append(path)

print()
print(f"{len(rule_files) - len(failed)}/{len(rule_files)} rules validated successfully.")

if failed:
    print("Failed rules:", ", ".join(failed))
    sys.exit(1)
