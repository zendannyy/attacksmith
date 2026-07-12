ATT&CKSMITH.mmd
```mermaid
%% ATT&CKSMITH Component Mappings
%% - Log/Signal Source: (TBD - external log sources)
%% - Log Generator: (TBD - scripts generating sample logs)
%% - Ingestion Pipeline: (TBD - log processing/normalization)
%% - Alerting Engine w/ Sigma Rules: (TBD - Sigma rule evaluation)
%% - Evaluator / Test Harness: run_collection_tests.py
%% - Test Orchestrator: run_collection_tests.sh
%% - Environment Hooks: normalize_logs.py, normalized_logs/, log_normalization.md
%% - Metrics & Reporting: (TBD - report generation/analysis)

flowchart LR for ATT&CKSmith
  A[Log/Signal Source] --> B[Log Generator]
  B --> C[Ingestion Pipeline]
  C --> D[Alerting Engine w/ Sigma Rules]
  D --> E[Evaluator / Test Harness]
  E --> F[Metrics & Reporting]
  subgraph Harness Controls
    G[Test Orchestrator]
    H[Environment Hooks]
  end
  G --> B
  G --> D
  H --> C
  E --> G
  F --> G



```

### Better Image of the above 
<br>
![Image of Design](/images/FlowChart.png)