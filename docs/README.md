## Project Title

Agentic AI for Detecting Malicious File System Activity on Linux Systems

## Team Information

Team Name: Aegis Team Members: Alexander Zucker, Aleksandre Zambakhidze, Shane Kirchoff

## Setup Instructions

After cloning the repo:
- python3 -m venv venv
- source venv/bin/activate
- pip install -r requirements.txt
- mkdir -p data/raw data/parsed data/processed src models results
- cd data/raw && wget https://zenodo.org/records/8196385/files/BGL.zip?download=1 && unzip BGL.zip* && rm BGL.zip* README.md

Processing BGL log data:
- python src/inspect_bgl.py --input data/raw/BGL.log
- python src/drain_parse.py
- python src/deleak_events.py --lower-threshold -1 --upper-threshold 0.99
- python src/window_events.py --input data/processed/bgl_structured_deleaked.csv --output data/processed/bgl_windows_deleaked.csv
- python src/build_features.py --input data/processed/bgl_windows_deleaked.csv --output data/processed/bgl_features_deleaked.csv
- python src/train_isolation_forest.py --input data/processed/bgl_features_deleaked.csv
- python src/train_lstm.py --input data/processed/bgl_windows_deleaked.csv --model-output models/lstm_event_classifier_deleaked.pt --vocab-output models/event_vocab_deleaked.json --predictions-output data/processed/lstm_predictions_deleaked.csv --epochs 10 --batch-size 512 --hidden-size 128 --embedding-dim 64 --dropout 0.3
- python src/sanity_check_lstm.py

## Problem to Solve

Our project addresses the difficulty of identifying malicious activity on Linux systems that are under attack by a stealthy threat actor. In a compromised environment, distinguishing malicious behavior from the enormous volume of normal file system activity is extremely challenging, yet it is critical for determining the scope of an intrusion and identifying persistence mechanisms that could allow re-compromise.

This problem matters because without reliable detection, defenders cannot contain an attacker or prevent them from regaining access after initial remediation. Our target beneficiaries are cybersecurity students participating in live cyberdefense competitions, where teams must defend intentionally vulnerable Windows/Linux VMs against an active red team. Rather than positioning this as an industry-grade commercial tool, we are building a lightweight, easily deployable agent that helps students learn to detect and respond to malicious activity in realistic adversarial scenarios.

## AI Functions to Be Developed

Our system focuses on machine learning and neural network-based anomaly detection, with the following capabilities:

Log sequence modeling using an LSTM neural network trained on ordered sequences of file system events, capturing behavioral patterns such as privilege escalation and lateral movement.
Unsupervised anomaly detection using an Isolation Forest baseline that flags statistical outliers without needing labeled training data.
Event classification and scoring that assigns each event (or window of events) an anomaly rating, confidence level, brief reasoning, and potentially a recommended action.
Log parsing and feature extraction via Drain parsing, windowing, and normalization to convert raw log text into structured inputs the models can consume.

## Use of Agentic AI

Agentic AI is central to how our system operates on a live compromised host rather than as a passive classifier:

Autonomous monitoring loop: The agent continuously ingests file system log events, parses them, and makes classification decisions without requiring a human to invoke it per event.
Multi-step reasoning over context: Because anomalies often only make sense across a sequence of events, the agent reasons over a window of recent activity rather than scoring events in isolation.
Coordination of multiple AI modules: The Isolation Forest and LSTM serve complementary roles — the agent uses both to cross-check flagged activity and reduce false positives before escalating.
Decision-making with feedback: Events flagged with high confidence are surfaced for human review, and the agent can recommend actions (e.g., investigate process, check persistence location), effectively triaging activity for a student defender rather than dumping raw logs on them.

## Dataset

Dataset name: BGL (Blue Gene/L supercomputer system logs)

Source: https://github.com/logpai/loghub/blob/master/BGL/README.md

Modality: Text (system log events)

Size: ~4.7 million log entries

Preprocessing plan: Drain parsing to convert raw log lines into event templates (e.g., E104) → windowing into sequences that can capture multi-step attack patterns → feature extraction (event count vectors for Isolation Forest, ordered event ID sequences for LSTM) → normalization.

For example, a parsed window might look like [E12, E12, E45, E9, E104, E9], which the LSTM consumes as a sequence while the Isolation Forest consumes it as counts (E12_count = 2, unique_events = 4, etc.).

## Evaluation Plan

Because of severe class imbalance between normal and anomalous log windows, accuracy is not a meaningful metric — a trivial model that labels everything "normal" would score very high while being operationally useless.

Primary metrics:

Precision, Recall, and F1 Score: our main evaluation criteria, with F1 used for model tuning on the validation set.
ROC-AUC: for a threshold-independent view of performance.
False Positive Rate:  critical because a tool that floods a defender with false alarms during a competition is worse than no tool at all.

Baseline comparison: Isolation Forest serves as the baseline. It requires no labels, trains in minutes on CPU, and gives us a solid benchmark. The LSTM is our primary model and must meaningfully outperform the baseline on F1 and FPR to be considered successful.

Success criteria: The project is successful if the LSTM achieves higher F1 and lower FPR than the Isolation Forest baseline on held-out BGL data, and if the final agent is lightweight enough to run on a competition VM without noticeable performance impact.

## Current Progress

Dataset acquired: BGL dataset downloaded and its structure confirmed.

Pipeline designed: End-to-end preprocessing pipeline (Drain parsing → windowing → feature extraction → normalization) has been fully designed.

Drain parser implementation in progress: Work is underway to convert raw log lines into stable event templates.

Model architecture defined: Both the Isolation Forest baseline (count-vector input) and LSTM (sequence input) have their input formats and training approaches specified.

No critical blockers encountered so far.

## Next-Step Plan

The IF is now doing its intended job well enough for the POC: trained on benign-only data, calibrated against held-out benign, and using an explicit threshold. The current 0.153295 threshold gives a reasonable operating point: low benign FPR with full malicious-window recall on the current labeled mixed set. More IF work now is likely to give diminishing returns compared to improving the supervised side.

Next highest-value steps:

1. Collect more attack telemetry
    - This is the biggest weakness right now.
    - The LSTM had validation issues because some attack families appeared only in validation, not training.
2. Relabel with stricter ambiguous handling
    - Mark framework-only staging/delivery artifacts as ambiguous.
    - Label attacker-visible behavior and target state changes as malicious.
    - This should reduce LSTM boundary noise.
    - Keep --min-malicious-events 5 for now.
    - Evaluate whether 3 improves recall without introducing noisy positives.
3. Recalibrate combined threshold
    - After retraining the LSTM, rerun:
        - evaluate_lstm.py
        - evaluate_models.py
        - calibrate_isolation_forest.py if IF model changes
    - Pick a new --combined-threshold if needed.
4. Add event/interval-level evaluation
    - Current combined evaluation is sequence-level.
    - The agent emits alert intervals, so interval-level precision/recall will better match actual analyst
        experience.

For the next collection round, run:

baseline generator duration: 90-120 minutes total
runs per chain: 3
gap between chains: 3-5 minutes
gap between repeated runs of same chain: 5-8 minutes
post-attack benign activity: 10-15 minutes

Randomize the order of the chains after the first iteration of them. Manually undo the damage caused by vandalism chains, and mark that activity as benign.

## Collecting Evaluation Data for IEEE Report

1. Freeze the current models and thresholds
    - Do not retrain during the report evaluation.
    - Record:
        - IF model file
        - LSTM model file
        - --iforest-threshold 0.153295
        - --combined-threshold 0.310117
        - audit rules / VM snapshot / baseline script version
2. Collect a fresh held-out evaluation session
    - Restore VM from snapshot.
    - Start auditd.
    - Start baseline workload.
    - Run each chain at least once, preferably 2-3 times if time allows.
    - Leave 3-5 min benign activity between chains.
    - Manually restore nginx/DNS after destructive chains.
    - Harvest:
        - audit.log
        - target_attack_windows.csv
3. Deploy the agent and scan the audit.log file on the target VM

    python3 src/aegis_triage_agent.py scan \
    --audit-log /var/log/audit/audit.log \
    --output-dir ~/aegis_eval_output \
    --device cpu
    
4. Score the raw audit log with the frozen agent

    .venv/bin/python src/score_audit_log.py \
    --raw-log data/raw/audit_eval_round1.log \
    --output-dir data/scored/eval_round1 \
    --iforest-threshold 0.153295 \
    --combined-threshold 0.310117 \
    --device cpu

5. Manually label the evaluation data
    - Parse and anchor the eval log.
    - Generate review slices.
    - Label malicious/benign/ambiguous.
    - Merge labels.
    - This gives ground truth for metrics.
6. Compute report metrics
    Use current evaluators:
    - IF window-level metrics: evaluate_isolation_forest.py
    - LSTM sequence-level metrics: evaluate_lstm.py
    - combined sequence-level metrics: evaluate_models.py

For the report, collect:

- IF held-out benign false-positive rate
- IF malicious-window recall
- LSTM precision / recall / F1 / ROC AUC
- combined precision / recall / F1
- number of alert intervals
- examples of true positives, false positives, false negatives
- runtime and output size for scoring a full log

Simply scoring a new audit.log gives detections, but not performance metrics unless you also label enough
of it to establish ground truth.