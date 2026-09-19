# TriageAI · NIST AI RMF assessment

Scope: a local analyst-assistance prototype for user-reported email alert triage.
Owner: the operator of this local installation. Assessment date: 18 September 2026.
Approval state: research use; no autonomous mailbox or identity-system actions.

## GOVERN

| Responsibility | Accountable role | Required evidence or control |
|---|---|---|
| Model and threshold ownership | Detection engineering lead | Review versioned model card, validation support, calibration results and limitations before enabling automation in a real SOC. |
| Label quality | SOC analyst; second reviewer for disputed labels | An override needs a reason. Disagreements require an explicit benign/malicious label. Agreement alone is not a label. |
| Change approval | Model owner and SOC manager | Compare a candidate with the incumbent on protected validation data; record promotion or rejection. Keep the prior artifact for rollback. |
| Data custody | Local operator | Restrict access to the workstation, raw mail and model files. Define retention before introducing real organizational mail. |
| Incident response | SOC incident commander | Own suspension, review backlog, scope analysis and recovery decisions. |

The LLM annotates a decision that has already been frozen. It cannot set the score,
change a tier, call tools, block a sender, reset credentials or erase an audit record.
All actions in an enrichment summary are suggestions for a human. Scores and tiers
remain visible beside the annotation so the analyst can identify contradictions.

Every completed analysis appends a decision ID, input hash, model version, timestamp,
score, tier, rule IDs and LLM-use state. Email contents and generated prose are excluded
from the audit. File locking and fsync protect concurrent writes; this is not an
immutable or tamper-evident enterprise log. A machine owner can alter it. A production
integration needs authenticated analysts, central audit retention and independent
change approval. Loopback binding is a local-use boundary, not user authentication.

## MAP

The intended users are SOC analysts reviewing employee-reported suspicious email.
The system prioritizes a queue and summarizes evidence. It does not establish that a
message is safe, attribute an adversary, or replace malware detonation and investigation.
Affected people include reporting employees, recipients, impersonated senders, analysts,
and any person whose details appear in a reported message.

| Harm | Trigger and affected party | Exposure boundary |
|---|---|---|
| Missed malicious email | Auto-close hides a credential lure; recipient may disclose credentials | Automation stays disabled without validation support; no message is deleted here. |
| Excess escalation | Legitimate reports consume analyst attention and delay real incidents | Measure benign fraction of escalations separately from the false-positive rate over all benign alerts. |
| Manipulated summary | Embedded instructions persuade the LLM to minimize evidence or recommend closing | Prompt controls, schema validation and fixed upstream decision reduce authority; prose can still mislead a reader. |
| Disclosure | Email includes personal or business information | Ollama is restricted to loopback; source mail is never sent to a remote API. Local process logs and disk remain exposure paths. |
| Unequal service | Historic English mail underrepresents other languages and writing styles | Report subgroup support; do not treat an AI-style signal as maliciousness or a finding about the sender. |
| Feedback poisoning | Incorrect analyst labels steer later models | Retain reasons, quarantine protected holdouts and near duplicates, require promotion checks. Local feedback has no authenticated identity. |

The evaluation queue's 85:15 mix is a scenario assumption, not a measured prevalence
claim about all SOCs. Enron ham and Nazario malicious mail differ in age, collection
method, formatting and headers. Labels may be predictable from source artifacts.
Historical phishing is presumed human-written for the optional style experiment;
that presumption is not ground-truth authorship. ATT&CK tags express hypotheses.

## MEASURE

The machine-readable record is `metrics.json`; `MODEL_CARD.md` explains training and
policy. The full test split and 85:15 evaluation stream overlap and are not independent
replications. Five-fold model comparison occurs only within training data. Validation
chooses thresholds; test measurements do not feed threshold selection.

| Question | Measure and evidence |
|---|---|
| Does ranking prioritize malicious reports? | PR-AUC, ROC-AUC, precision, recall, F1 and FPR at 95% / 99% recall in the model card. |
| Is auto-close supported? | Malicious / auto-closed, missed malicious / all malicious, closed count, automation fraction and a one-sided 95% Wilson upper bound. |
| Are escalations useful? | Malicious / escalated, benign / escalated, benign escalated / all benign, and escalation count. |
| Is work saved? | Replay median time includes scoring, fallback/schema and audit. Estimated labor savings assume five minutes per auto-close and are not observed savings. |
| Does LLM manipulation succeed? | Thirty categorized payloads in `REDTEAM_REPORT.md`; live generation and fallback are separate columns. Missing Ollama means live coverage is absent, never a pass. |
| Does preprocessing resist evasion? | Five transformations of held-out malicious mail; clean, ablated and mitigated recall. The same model is used, so this is a preprocessing ablation. |
| Do errors differ by group? | `BATCH_REPORT.json` groups by source, sender domain and a coarse non-ASCII proxy, with minimum support ten. The proxy is not language identification. |
| Has the distribution moved? | Weekly PSI against fixed training bins on six selected indicators and scores; values above 0.2 trigger review. Small samples are flagged. |

Prompt-leakage tests detect the private test sentinel and exact instruction fragments.
They do not establish absence of paraphrase disclosure. Schema-valid text can still be
false or unsafe advice. A successful offline test suite is not live-model robustness.
The public replay is not sufficient evidence to approve autonomous SOC operations.

## MANAGE

| Condition | Response | Owner |
|---|---|---|
| Insufficient threshold support | Keep the relevant tier disabled; route alerts to analyst review. Gather independently adjudicated reports. | Detection lead |
| Ollama down, timeout or invalid output | Preserve the completed tier, use a deterministic summary and display a warning. | Analyst |
| PSI > 0.2 | Investigate source changes, language mix, collection faults and campaigns. Review recent errors before retraining. Do not auto-promote from drift alone. | Model owner |
| Worse validation auto-close error | Refuse candidate promotion; retain the current artifact and write the failure to the changelog. | Model owner |
| Summary contradicts evidence | Ignore the suggestion, record feedback and preserve the source email under local retention policy. | Analyst |
| Suspected artifact compromise | Stop using the artifact, disable automation, preserve hashes/logs, inspect recent closed alerts, identify affected credentials and invoke the SOC incident process. | Incident commander |

Recovery from compromise requires a known-good artifact or a clean retrain from reviewed
inputs, independent validation and explicit operational approval. Joblib files can execute
code when loaded: only locally produced, trusted artifacts belong in the model directory.
The code cannot establish that an arbitrary downloaded artifact is safe.

Run drift weekly with a local scheduler after collecting timestamped observations.
Retraining is a separate manual step; a passing gate permits an explicit promotion flag.
Repeated selection against the same validation set can overfit that set. Refresh a
quarantined, independently labeled acceptance set before repeated production promotions.
Auto-close policy bounds concern the evaluated distribution, not future guarantees.

Sources: [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework),
[NIST Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook),
[OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/),
[MITRE phishing](https://attack.mitre.org/techniques/T1566/).
