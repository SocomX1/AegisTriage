# Aegis Triage Report

- Generated: `2026-05-09 21:00:39 UTC`
- Input: `data/processed/combined_events.csv`
- Output directory: `/home/alex/AegisTriage/data/scored/agent_smoke`
- Alert intervals: `11`
- Positive sequences: `584`
- Combined threshold: `0.310117`
- LSTM weight: `0.7`

> Model caveat: this is a proof-of-concept report. Current models are useful for pipeline validation, but require more benign telemetry, repeated attack runs, and cleaner ambiguous labeling before production use.

## Alert Intervals

### Alert 3

- Time: `1778300215.361` to `1778300233.013`
- Duration seconds: `17.652`
- Sequences/events: `110` / `5620`
- Max combined score: `0.999853`
- Max LSTM probability: `0.999790`
- Max IF anomaly score: `0.256495`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `id -u (75)`
- `date +%s (56)`
- `cat (32)`

Top audit keys:
- `exec:2003`
- `privilege_transition:1464`
- `network_connect:969`

Top executables:
- `/usr/sbin/sshd:2014`
- `/usr/bin/dash:627`
- `/usr/bin/sudo:366`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:1876`
- `/run/systemd/userdb/io.systemd.DynamicUser:644`
- `/bin/sh:573`

### Alert 5

- Time: `1778300358.325` to `1778300359.54`
- Duration seconds: `1.215`
- Sequences/events: `71` / `1168`
- Max combined score: `0.983031`
- Max LSTM probability: `0.999802`
- Max IF anomaly score: `0.234668`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `id -u (14)`
- `/usr/bin/locale-check C.UTF-8 (14)`
- `locale (14)`

Top audit keys:
- `privilege_transition:457`
- `network_connect:250`
- `exec:178`

Top executables:
- `/usr/bin/sudo:612`
- `/usr/libexec/netplan/generate:51`
- `/usr/lib/systemd/systemd-executor:49`

Top paths:
- `/var/run/nscd/socket:254`
- `/lib64/ld-linux-x86-64.so.2:201`
- `/dev/log:40`

### Alert 7

- Time: `1778300426.441` to `1778300428.461`
- Duration seconds: `2.020`
- Sequences/events: `62` / `776`
- Max combined score: `0.979458`
- Max LSTM probability: `0.999823`
- Max IF anomaly score: `0.230017`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `id -u (10)`
- `/usr/bin/locale-check C.UTF-8 (9)`
- `locale (9)`

Top audit keys:
- `privilege_transition:276`
- `exec:153`
- `network_connect:130`

Top executables:
- `/usr/bin/sudo:369`
- `/usr/libexec/netplan/generate:34`
- `/usr/bin/mkdir:30`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:161`
- `/var/run/nscd/socket:130`
- `/tmp/:28`

### Alert 9

- Time: `1778300598.586` to `1778300610.761`
- Duration seconds: `12.175`
- Sequences/events: `78` / `5780`
- Max combined score: `0.973222`
- Max LSTM probability: `0.999572`
- Max IF anomaly score: `0.222159`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `id -u (91)`
- `date +%s (73)`
- `/bin/sh -e /usr/lib/ubuntu-release-upgrader/release-upgrade-motd (37)`

Top audit keys:
- `exec:2274`
- `privilege_transition:1588`
- `network_connect:1107`

Top executables:
- `/usr/sbin/sshd:2592`
- `/usr/bin/dash:809`
- `/usr/bin/cat:203`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:2108`
- `/run/systemd/userdb/io.systemd.DynamicUser:792`
- `/bin/sh:734`

### Alert 4

- Time: `1778300281.107` to `1778300287.597`
- Duration seconds: `6.490`
- Sequences/events: `19` / `1833`
- Max combined score: `0.969130`
- Max LSTM probability: `0.999738`
- Max IF anomaly score: `0.216702`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `date -Is (27)`
- `id -u (25)`
- `date +%s (18)`

Top audit keys:
- `exec:684`
- `privilege_transition:405`
- `network_connect:296`

Top executables:
- `/usr/sbin/sshd:686`
- `/usr/bin/bash:206`
- `/usr/bin/dash:202`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:642`
- `docs/:252`
- `/run/systemd/userdb/io.systemd.DynamicUser:206`

### Alert 10

- Time: `1778300644.587` to `1778300647.756`
- Duration seconds: `3.169`
- Sequences/events: `33` / `1759`
- Max combined score: `0.963082`
- Max LSTM probability: `0.999582`
- Max IF anomaly score: `0.208998`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `id -u (25)`
- `date +%s (18)`
- `/usr/sbin/sshd -D -R (9)`

Top audit keys:
- `privilege_transition:601`
- `exec:564`
- `network_connect:341`

Top executables:
- `/usr/sbin/sshd:648`
- `/usr/bin/sudo:325`
- `/usr/bin/dash:199`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:526`
- `/var/run/nscd/socket:202`
- `/run/systemd/userdb/io.systemd.DynamicUser:198`

### Alert 8

- Time: `1778300435.072` to `1778300439.199`
- Duration seconds: `4.127`
- Sequences/events: `182` / `1894`
- Max combined score: `0.959850`
- Max LSTM probability: `0.999825`
- Max IF anomaly score: `0.204587`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `id -u (30)`
- `/usr/bin/locale-check C.UTF-8 (29)`
- `locale (29)`

Top audit keys:
- `privilege_transition:862`
- `exec:382`
- `network_connect:348`

Top executables:
- `/usr/bin/sudo:1189`
- `/usr/sbin/xtables-nft-multi:202`
- `/usr/bin/bash:105`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:411`
- `/var/run/nscd/socket:378`
- `/sbin/ip6tables:164`

### Alert 0

- Time: `1778298833.783` to `1778300128.067`
- Duration seconds: `1294.284`
- Sequences/events: `16` / `374`
- Max combined score: `0.915408`
- Max LSTM probability: `0.998473`
- Max IF anomaly score: `0.148183`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `tr [:upper:] [:lower:] (18)`
- `cut -c1 (9)`
- `tr [:lower:] [:upper:] (9)`

Top audit keys:
- `exec:173`
- `privilege_transition:66`
- `(null):44`

Top executables:
- `/usr/bin/sudo:86`
- `/usr/sbin/auditctl:45`
- `/usr/bin/dash:32`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:164`
- `/usr/bin/tr:54`
- `/var/run/nscd/socket:48`

### Alert 1

- Time: `1778300135.684` to `1778300138.298`
- Duration seconds: `2.614`
- Sequences/events: `3` / `73`
- Max combined score: `0.775507`
- Max LSTM probability: `0.809885`
- Max IF anomaly score: `0.137951`
- Reason summary: `lstm_and_iforest`

Top commands:
- `grep -E overlayroot`
- `/media/root-ro`
- `/media/root-rw /proc/mounts (1)`

Top audit keys:
- `exec:35`
- `home_activity:15`
- `network_connect:9`

Top executables:
- `/usr/sbin/sshd:15`
- `/usr/bin/mkdir:13`
- `/usr/bin/dash:8`

Top paths:
- `/lib64/ld-linux-x86-64.so.2:29`
- `/run/systemd/userdb/io.systemd.DynamicUser:14`
- `/usr/bin/date:8`

### Alert 6

- Time: `1778300395.846` to `1778300398.891`
- Duration seconds: `3.045`
- Sequences/events: `5` / `145`
- Max combined score: `0.744356`
- Max LSTM probability: `0.889216`
- Max IF anomaly score: `0.025542`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `systemctl status nginx --no-pager (1)`
- `sleep 1 (1)`
- `sudo -n systemctl status ssh --no-pager (1)`

Top audit keys:
- `privilege_transition:91`
- `network_connect:32`
- `home_activity:4`

Top executables:
- `/usr/bin/sudo:125`
- `/usr/bin/systemctl:4`
- `/usr/bin/sleep:2`

Top paths:
- `/var/run/nscd/socket:32`
- `/lib64/ld-linux-x86-64.so.2:6`
- `/home/analyst/:4`

### Alert 2

- Time: `1778300187.589` to `1778300191.653`
- Duration seconds: `4.064`
- Sequences/events: `5` / `131`
- Max combined score: `0.674728`
- Max LSTM probability: `0.817092`
- Max IF anomaly score: `0.000719`
- Reason summary: `iforest_only|lstm_and_iforest`

Top commands:
- `sleep 2 (2)`
- `systemctl status nginx --no-pager (1)`
- `sudo -n systemctl status ssh --no-pager (1)`

Top audit keys:
- `privilege_transition:76`
- `network_connect:32`
- `home_activity:4`

Top executables:
- `/usr/bin/sudo:110`
- `/usr/bin/systemctl:4`
- `/usr/bin/sleep:2`

Top paths:
- `/var/run/nscd/socket:32`
- `/lib64/ld-linux-x86-64.so.2:6`
- `/home/analyst/:4`

## Generated Files

- `parsed_events.csv`
- `iforest_windows.csv`
- `iforest_scores.csv`
- `lstm_sequence_scores.csv`
- `combined_sequence_scores.csv`
- `ranked_alerts.csv`
- `alert_intervals.csv`
- `triage_summary.json`
