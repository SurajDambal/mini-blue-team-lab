# Mini Blue Team Lab: Attack Simulation & Automated Detection

InternNova Cybersecurity Week 6, Project 12 (Defensive Security).

A small offline purple-team lab. One script plays 8 attacks (as log lines),
another script acts like a mini SIEM and tries to detect them. Then it checks
its own alerts against a "ground truth" file to see what it caught and missed.

**Important:** everything is simulated. The scripts only write and read text
log files. Nothing is attacked and no network traffic is sent. It is not
Wazuh/Splunk; porting these rules to one of them is the next step.

## Files

| File | What it does |
|---|---|
| `simulate_attacks.py` | The "attacker" box. Writes `auth.log`, `firewall.log`, `access.log` (normal noise + 8 attacks) and `ground_truth.json` |
| `detect.py` | The "SIEM". Normalizes the 3 log formats, runs detection rules, scores them against the ground truth, builds an incident timeline |
| `sample-data/` | Logs from one run |
| `results/` | Output of rule set v1, v2 and the incident timeline |
| `docs/` | One-page project report |

## Run it

Needs Python 3.8+ and nothing else.

```bash
python3 simulate_attacks.py   # creates the logs + ground_truth.json
python3 detect.py v1          # first rule set
python3 detect.py v2          # v1 + the rule I added after a miss
```

## Attack -> Detection (MITRE ATT&CK)

| ID | Technique | Simulated attack | v1 | v2 |
|---|---|---|---|---|
| A1 | T1110.001 | SSH brute force (fast) | caught | caught |
| A2 | T1078 | Valid account login after failures | caught | caught |
| A3 | T1136.001 | Backdoor user created | caught | caught |
| A4 | T1548.003 | Root shell via sudo | caught | caught |
| A5 | T1053.003 | Cron job persistence | caught | caught |
| A6 | T1110.001 | SSH brute force (low and slow) | **missed** | caught |
| A7 | T1046 | TCP port scan | caught | caught |
| A8 | T1190 | SQL injection | caught | caught |

v1 caught 7/8. The slow brute force tried once every ~5 minutes, so it never
hit "10 failures in 5 minutes". v2 adds a 1-hour window rule: 8/8, 0 false
positives on the normal activity.

## Limits

- Data is synthetic, so real logs will be messier.
- Thresholds (10 failures, 15 ports) are tuned for this dataset.
- Admin allowlist (`sanjay`, `priya`) is hardcoded.
