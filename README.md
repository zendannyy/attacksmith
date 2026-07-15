## README.md

models is the foundation to the rest of the project, the scaffolding. 
It defines the data contracts every other component exchanges

Key components of models.py 
- RawLogRecord: generator output (source + opaque payload + ATT&CK metadata)
- IngestedRecord: raw + ingestion metadata (id, ingested_at)
- NormalizedEvent: canonical schema for Sigma (event_kind, fields, tags, dotted get())
- Alert: rule match result (rule_id, event_id, matched_fields)
- TestCase / TestResult: harness contract (expected_rules, must_not_match, min_alerts)


From here, a high-level Flow chart is seen at [ATT&CKSMITH.md](./ATT&CKSMITH.md)
