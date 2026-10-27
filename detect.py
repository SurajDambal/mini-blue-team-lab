"""detect.py - the 'SIEM' of my mini blue-team lab.

Pipeline:  raw logs -> normalize into events -> detection rules -> alerts
           -> compare with ground_truth.json -> coverage + false positives
           -> incident timeline for the attack chain

Usage:  python3 detect.py v1      (first rule set)
        python3 detect.py v2      (v1 + the rule I added after a miss)
"""
import re
import sys
import json
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote

VERSION = sys.argv[1] if len(sys.argv) > 1 else "v2"
YEAR = 2026
ADMINS = {"sanjay", "priya"}          # people who are allowed to sudo to a shell / edit cron

# ---------------- 1. NORMALIZE ----------------
SYS_TS = r"(\w{3}\s+\d+ \d\d:\d\d:\d\d)"
P = {
    "ssh_fail": re.compile(SYS_TS + r" \S+ sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+)"),
    "ssh_ok": re.compile(SYS_TS + r" \S+ sshd\[\d+\]: Accepted \w+ for (\S+) from (\S+)"),
    "useradd": re.compile(SYS_TS + r" \S+ useradd\[\d+\]: new user: name=(\S+),"),
    "sudo": re.compile(SYS_TS + r" \S+ sudo: (\S+) : .*COMMAND=(.*)$"),
    "cron": re.compile(SYS_TS + r" \S+ crontab\[\d+\]: \((\S+)\) REPLACE"),
    "fw": re.compile(SYS_TS + r" \S+ kernel: DROP .*SRC=(\S+) .*DPT=(\d+)"),
    "web": re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3})'),
}


def sts(s):
    return datetime.strptime(f"{YEAR} {s}", "%Y %b %d %H:%M:%S")


def normalize():
    """turn every log line into one common dict: {time, type, ip, user, ...}"""
    ev = []
    for line in open("auth.log"):
        if m := P["ssh_fail"].match(line):
            ev.append({"time": sts(m[1]), "type": "ssh_fail", "user": m[2], "ip": m[3], "raw": line.strip()})
        elif m := P["ssh_ok"].match(line):
            ev.append({"time": sts(m[1]), "type": "ssh_ok", "user": m[2], "ip": m[3], "raw": line.strip()})
        elif m := P["useradd"].match(line):
            ev.append({"time": sts(m[1]), "type": "useradd", "user": m[2], "raw": line.strip()})
        elif m := P["sudo"].match(line):
            ev.append({"time": sts(m[1]), "type": "sudo", "user": m[2], "cmd": m[3], "raw": line.strip()})
        elif m := P["cron"].match(line):
            ev.append({"time": sts(m[1]), "type": "cron", "user": m[2], "raw": line.strip()})
    for line in open("firewall.log"):
        if m := P["fw"].match(line):
            ev.append({"time": sts(m[1]), "type": "fw_drop", "ip": m[2], "port": int(m[3]), "raw": line.strip()})
    for line in open("access.log"):
        if m := P["web"].match(line):
            t = datetime.strptime(m[2].split()[0], "%d/%b/%Y:%H:%M:%S")
            ev.append({"time": t, "type": "web", "ip": m[1], "url": unquote(m[4]), "status": m[5], "raw": line.strip()})
    ev.sort(key=lambda e: e["time"])
    return ev


# ---------------- 2. RULES ----------------
alerts = []


def alert(rule, tech, sev, ev_time, key, ip, detail):
    alerts.append({"rule": rule, "technique": tech, "severity": sev,
                   "time": ev_time.strftime("%H:%M:%S"), "key": key, "ip": ip, "detail": detail})


def window_hit(times, n, window):
    times = sorted(times)
    for i in range(len(times) - n + 1):
        if times[i + n - 1] - times[i] <= window:
            return times[i + n - 1]


def run_rules(ev):
    fails = defaultdict(list)
    for e in ev:
        if e["type"] == "ssh_fail":
            fails[e["ip"]].append(e["time"])

    # R1 fast brute force: 10 failures in 5 minutes from one IP
    bf_time = {}
    for ip, ts in fails.items():
        if h := window_hit(ts, 10, timedelta(minutes=5)):
            bf_time[ip] = h
            alert("ssh_bruteforce", "T1110.001", "High", h, ip, ip, f"{len(ts)} failed logins")

    # R2 successful login from an IP that just brute-forced
    for e in ev:
        if e["type"] == "ssh_ok" and e["ip"] in bf_time and e["time"] >= bf_time[e["ip"]]:
            alert("success_after_bruteforce", "T1078", "Critical", e["time"], e["ip"], e["ip"],
                  f"account '{e['user']}' logged in after the brute force")

    # R3 new local user
    for e in ev:
        if e["type"] == "useradd":
            alert("new_user_created", "T1136.001", "High", e["time"], e["user"], None, f"new account {e['user']}")

    # R4 root shell through sudo by someone who is not an admin
    for e in ev:
        if e["type"] == "sudo" and re.search(r"/bin/(ba|z)?sh\s*$", e["cmd"]) and e["user"] not in ADMINS:
            alert("sudo_root_shell", "T1548.003", "High", e["time"], e["user"], None, f"{e['user']} ran {e['cmd']} as root")

    # R5 crontab edited by a non-admin
    for e in ev:
        if e["type"] == "cron" and e["user"] not in ADMINS:
            alert("crontab_modified", "T1053.003", "Medium", e["time"], e["user"], None, f"{e['user']} changed their crontab")

    # R6 port scan: 15 different ports dropped from one IP within 60 seconds
    ports = defaultdict(list)
    for e in ev:
        if e["type"] == "fw_drop":
            ports[e["ip"]].append((e["time"], e["port"]))
    for ip, pts in ports.items():
        pts.sort()
        for i in range(len(pts)):
            seen = {p for t, p in pts if pts[i][0] <= t <= pts[i][0] + timedelta(seconds=60)}
            if len(seen) >= 15:
                alert("port_scan", "T1046", "Medium", pts[i][0], ip, ip, f"{len(seen)} different ports in 60s")
                break

    # R7 SQL injection patterns in the URL
    sqli = re.compile(r"(union\s+select|'\s*or\s+'1'\s*=\s*'1|drop\s+table|--\s*$)", re.I)
    seen_ip = set()
    for e in ev:
        if e["type"] == "web" and sqli.search(e["url"]) and e["ip"] not in seen_ip:
            seen_ip.add(e["ip"])
            alert("web_sqli", "T1190", "High", e["time"], e["ip"], e["ip"], f"payload: {e['url']}")

    # R1b (added in v2): slow brute force, 10 failures inside ONE HOUR
    if VERSION == "v2":
        for ip, ts in fails.items():
            if ip in bf_time:
                continue
            if h := window_hit(ts, 10, timedelta(hours=1)):
                alert("ssh_bruteforce_slow", "T1110.001", "Medium", h, ip, ip, f"{len(ts)} failures spread over an hour")


# ---------------- 3. CHECK AGAINST GROUND TRUTH ----------------
def score():
    truth = json.load(open("ground_truth.json"))
    got = {(a["rule"], a["key"]) for a in alerts}
    rows = []
    for t in truth:
        rows.append({**t, "detected": (t["expected_rule"], t["key"]) in got})
    expected = {(t["expected_rule"], t["key"]) for t in truth}
    false_pos = [a for a in alerts if (a["rule"], a["key"]) not in expected]
    return rows, false_pos


# ---------------- 4. INCIDENT TIMELINE ----------------
def timeline():
    chain = [a for a in alerts if a["rule"] in
             ("ssh_bruteforce", "success_after_bruteforce", "new_user_created", "sudo_root_shell", "crontab_modified")]
    chain.sort(key=lambda a: a["time"])
    return chain


if __name__ == "__main__":
    ev = normalize()
    run_rules(ev)
    rows, fps = score()
    hit = sum(r["detected"] for r in rows)
    print(f"[{VERSION}] events normalized: {len(ev)} | alerts: {len(alerts)}")
    print(f"{'ID':3} {'Technique':10} {'Attack':36} Detected")
    for r in rows:
        print(f"{r['id']:3} {r['technique']:10} {r['name']:36} {'YES' if r['detected'] else 'MISSED'}")
    print(f"coverage: {hit}/{len(rows)} | false positives: {len(fps)}")
    for f in fps:
        print("  FP:", f)
    json.dump({"version": VERSION, "events": len(ev), "alerts": alerts, "coverage": rows,
               "false_positives": fps}, open(f"results_{VERSION}.json", "w"), indent=2)
    if VERSION == "v2":
        lines = ["INCIDENT TIMELINE - attacker " + "198.51.100.23", "-" * 60]
        for a in timeline():
            lines.append(f"{a['time']}  [{a['severity']:8}] {a['technique']:10} {a['detail']}")
        lines += ["", "RESPONSE", "1. Block 198.51.100.23 at the firewall.",
                  "2. Lock 'admin' and 'svc_backup', kill their sessions, reset admin password.",
                  "3. Delete the svc_backup user and its crontab entry; check /home/svc_backup for tools.",
                  "4. Disable SSH password login (keys only) and add fail2ban.",
                  "5. Keep the slow brute-force rule: that attacker (203.0.113.99) evaded the 5-minute rule."]
        open("incident_timeline.txt", "w").write("\n".join(lines) + "\n")
        print("\n" + "\n".join(lines))
