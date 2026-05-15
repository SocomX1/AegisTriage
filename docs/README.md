## Project Title

Aegis: Agentic AI for detecting malicious file system activity on Linux systems

## Team Information

Team Members: Alexander Zucker, Aleksandre Zambakhidze, Shane Kirchoff

## Problem Statement

Our project addresses the difficulty of identifying malicious activity on Linux systems that are under attack by a stealthy threat actor. In a compromised environment, distinguishing malicious behavior from the enormous volume of normal file system activity is extremely challenging, yet it is critical for determining the scope of an intrusion and identifying persistence mechanisms that could allow re-compromise.

This problem matters because without reliable detection, defenders cannot contain an attacker or prevent them from regaining access after initial remediation. This project is intended to be used by 
cybersecurity students participating in live cyberdefense competitions, where teams must defend intentionally vulnerable Windows/Linux VMs against an active red team. Rather than positioning this as an industry-grade commercial tool, we are building a lightweight, easily deployable agent that helps students learn to detect and respond to malicious activity in realistic adversarial scenarios.

## Usage Instructions

### Scoring Existing Audit Logs

Use this workflow when you already have an `audit.log` file, or when you want
to pull audit logs from a target VM and score them locally.

1. Clone the repository.

    ```bash
    git clone <repo-url>
    cd AegisTriage
    ```

2. Create and activate a Python virtual environment.

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

3. Confirm the trained model artifacts are present.

    ```bash
    ls models/isolation_forest.joblib \
       models/isolation_forest_features.json \
       models/lstm_classifier.pt \
       data/model/window_feature_schema.json \
       data/model/lstm_vocab.json
    ```

4. If you already have an audit log, place it under `data/raw/`.

    ```bash
    mkdir -p data/raw data/scored
    cp /path/to/audit.log data/raw/audit_eval.log
    ```

5. Score the local audit log.

    ```bash
    .venv/bin/python src/scoring/score_audit_log.py \
      --raw-log data/raw/audit_eval.log \
      --output-dir data/scored/audit_eval \
      --device cpu
    ```

6. Review the scoring outputs.

    ```bash
    ls data/scored/audit_eval
    less data/scored/audit_eval/alert_intervals.csv
    less data/scored/audit_eval/ranked_alerts.csv
    ```

7. To harvest audit logs from a target system instead, make sure SSH key
   authentication works for the target VM, then run:

    ```bash
    SSH_USER=analyst utility_scripts/harvest_audit_logs.sh \
      <target-host-or-ip> \
      data/raw/audit_harvested.log
    ```

8. Score the harvested log.

    ```bash
    .venv/bin/python src/scoring/score_audit_log.py \
      --raw-log data/raw/audit_harvested.log \
      --output-dir data/scored/audit_harvested \
      --device cpu
    ```

### Deploying the Agent

Use this workflow when you want the target VM to run the Aegis agent locally
against its own audit logs.

1. From the local repository, confirm the trained model artifacts are present.

    ```bash
    ls models/isolation_forest.joblib \
       models/isolation_forest_features.json \
       models/lstm_classifier.pt \
       data/model/window_feature_schema.json \
       data/model/lstm_vocab.json
    ```

2. Deploy the agent bundle to the target system.

    ```bash
    utility_scripts/deploy_agent.sh \
      analyst@<target-host-or-ip>:/home/analyst/aegis-triage-agent
    ```

3. SSH into the target system.

    ```bash
    ssh analyst@<target-host-or-ip>
    cd /home/analyst/aegis-triage-agent
    ```

4. Copy the current audit log to a readable temporary location.

    ```bash
    sudo cp /var/log/audit/audit.log /tmp/audit.log
    sudo chown "$(id -un):$(id -gn)" /tmp/audit.log
    ```

5. Run the deployed agent against the target audit log.

    ```bash
    .venv/bin/python src/agent/aegis_triage_agent.py scan \
      --audit-log /tmp/audit.log \
      --output-dir data/scored/vm_scan \
      --device cpu
    ```

6. Review the generated triage report on the target.

    ```bash
    less data/scored/vm_scan/triage_report.md
    less data/scored/vm_scan/triage_summary.json
    ```

7. Optional: copy the agent output back to the local machine for report review.

    ```bash
    scp -r analyst@<target-host-or-ip>:/home/analyst/aegis-triage-agent/data/scored/vm_scan \
      data/scored/
    ```

### Training and Evaluating Models

See `docs/model_tuning.md`.

## Current Progress and Next Steps

The IF is now doing its intended job well enough for the POC: trained on benign-only data, calibrated against held-out benign, and using an explicit threshold. The current 0.153295 threshold gives a reasonable operating point: low benign FPR with full malicious-window recall on the current labeled mixed set. More IF work now is likely to give diminishing returns compared to improving the supervised side.

### Next Steps to Improve Model Performance

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

For the next collection round, use the following guidelines:

- Baseline generator duration: 90-120 minutes total
- Runs per chain: 3
- Gap between chains: 3-5 minutes
- Gap between repeated runs of same chain: 5-8 minutes
- Post-attack benign activity: 10-15 minutes
- Randomize the order of the chains after the first iteration of them. Manually undo the damage caused by vandalism chains, and mark that activity as benign.

### Collecting Evaluation Data

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

    python3 src/agent/aegis_triage_agent.py scan \
    --audit-log /var/log/audit/audit.log \
    --output-dir ~/aegis_eval_output \
    --device cpu
    
4. Score the raw audit log with the frozen agent

    .venv/bin/python src/scoring/score_audit_log.py \
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

Collect the following data:

- IF held-out benign false-positive rate
- IF malicious-window recall
- LSTM precision / recall / F1 / ROC AUC
- combined precision / recall / F1
- number of alert intervals
- examples of true positives, false positives, false negatives
- runtime and output size for scoring a full log

Simply scoring a new audit.log gives detections, but not performance metrics unless you also label enough
of it to establish ground truth.
