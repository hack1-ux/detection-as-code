# Detection-as-Code Pipeline

A Sigma-based detection engineering pipeline that treats SIEM detection rules like software: version-controlled, validated against real attack telemetry, and mapped to MITRE ATT&CK.

## Overview

This project demonstrates an end-to-end detection engineering workflow:

1. Real attack telemetry (Windows Event Logs / Sysmon) is converted from EVTX to JSON and loaded into a Wazuh SIEM (built on OpenSearch).
2. Detection logic is written in [Sigma](https://github.com/SigmaHQ/sigma), a vendor-neutral rule format.
3. Rules are automatically converted to OpenSearch/Lucene queries using [pySigma](https://github.com/SigmaHQ/pySigma).
4. Each rule is validated by running its converted query against the indexed attack data, confirming it actually fires on the technique it targets.

Every rule in this repo has been tested against real (historical, publicly available) attack evidence — not just written and assumed to work.

## Stack

- **SIEM:** Wazuh 4.9.0 (single-node Docker deployment: manager, indexer, dashboard)
- **Detection format:** Sigma
- **Conversion:** pySigma + pysigma-backend-opensearch
- **Attack data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (public, real-world attack technique captures)
- **Environment:** WSL2 (Ubuntu) on Windows 11

## Rules

| # | Tactic | Rule | MITRE ATT&CK | Validated |
|---|---|---|---|---|
| 1 | Discovery | SharpHound/BloodHound SAMR pipe enumeration | T1087.002 | ✅ 5/5 |
| 2 | Credential Access | Mimikatz Memssp credential logging via LSASS | T1003.001 | ✅ 1/1 |
| 3 | Persistence | Suspicious BITS job targeting cmd.exe | T1197 | ✅ 2/2 |
| 4 | Lateral Movement | Process spawned by WinRM host (wsmprovhost.exe) | T1021.006 | ✅ 1/1 |
| 5 | Execution | Regsvr32 Squiblydoo remote scriptlet execution | T1218.010 | ✅ 1/1 |
| 6 | Defense Evasion | Windows Security event log cleared | T1070.001 | ✅ 1/1 |
| 7 | Command and Control | SSH tunneling via Plink (PuTTY) | T1572 | ✅ 1/1 |
| 8 | Privilege Escalation | UAC bypass via Eventvwr.exe registry hijack | T1548.002 | ✅ 1/1 |
| 9 | Execution / Defense Evasion | Rundll32 loading non-DLL extension as library | T1218.011 | ✅ 1/1 |

Each rule's YAML lives under `rules/<tactic>/`, with full description, references, and false-positive notes.

## How validation works

For each rule:
1. Real attack event data is inspected in the Wazuh index to identify the actual field structure and values.
2. A Sigma rule is written targeting that structure.
3. `convert_rule.py` uses pySigma to convert the rule into an OpenSearch query.
4. That exact query is run against the index via the OpenSearch `_search` API.
5. The result is compared against the known-malicious event(s) to confirm a match.

```bash
python convert_rule.py rules/discovery/samr_pipe_recon.yml
# → Event.System.EventID:5145 AND Event.EventData.RelativeTargetName:samr
```

## Repo structure

detection-as-code/
├── rules/ # Sigma rules, organized by MITRE ATT&CK tactic
│ ├── discovery/
│ ├── credential-access/
│ ├── persistence/
│ ├── lateral-movement/
│ ├── execution/
│ ├── defense-evasion/
│ ├── command-and-control/
│ └── privilege-escalation/
├── sample-logs/ # Helper scripts for EVTX → JSON conversion and bulk indexing
├── convert_rule.py # Converts a Sigma rule to an OpenSearch query using pySigma
└── README.md


## Known data-handling notes

- Some Windows telemetry fields use values Elasticsearch/OpenSearch's default `long` type can't hold (e.g. `18446744073709551615` representing "unlimited"), causing a small percentage of bulk-indexed documents to be rejected. This is a known quirk of raw Windows event data and doesn't affect rule validity.
- String fields in this index are `text`-analyzed by default; exact/wildcard matches on values like file paths require querying the `.keyword` subfield (e.g. `Event.EventData.Image.keyword`).

## Roadmap

- [ ] Expand to 15-20 rules covering remaining technique variety
- [ ] GitHub Actions CI: automatically validate and convert every rule on push
- [ ] Streamlit dashboard visualizing ATT&CK technique coverage

## Author

Muhammad Sudais — Blue Team Cybersecurity Analyst, CEH
[GitHub](https://github.com/hack1-ux) · [LinkedIn](https://linkedin.com/in/muhammad-sudais-a1b56625b)
