import sys
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend

rule_path = sys.argv[1] if len(sys.argv) > 1 else "rules/discovery/samr_pipe_recon.yml"

with open(rule_path) as f:
    rule_yaml = f.read()

rules = SigmaCollection.from_yaml(rule_yaml)
backend = OpensearchLuceneBackend()
queries = backend.convert(rules)

for q in queries:
    print(q)
