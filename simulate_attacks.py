"""simulate_attacks.py - the 'attacker box' of my mini blue-team lab.

It does NOT attack anything. It only writes log lines (as if three machines
produced them) so I can test my detections safely, fully offline.

Outputs:
  auth.log      sshd / sudo / useradd / crontab lines  (Linux target)
  firewall.log  iptables-style drop lines              (firewall)
  access.log    web server lines                       (web target)
  ground_truth.json  what I *really* did, so I can check if detections caught it
"""
import json
import random
from datetime import datetime, timedelta

random.seed(7)
T0 = datetime(2026, 10, 26, 9, 0, 0)

auth, fw, web, truth = [], [], [], []


def sys_ts(t):
    return t.strftime("%b %e %H:%M:%S")


def web_ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0530")


def A(t, msg):
    auth.append((t, f"{sys_ts(t)} target-linux {msg}"))


def pid():
    return random.randint(1200, 9800)


# ------------------------------------------------------------------
# BENIGN NOISE (a good detection must stay quiet on all of this)
# ------------------------------------------------------------------
for i in range(25):
    t = T0 + timedelta(minutes=random.randint(0, 240))
    u = random.choice(["sanjay", "priya"])
    A(t, f"sshd[{pid()}]: Accepted publickey for {u} from 10.0.0.{random.choice([12, 15])} port {random.randint(40000, 60000)} ssh2")

# priya fat-fingers her password 3 times
t = T0 + timedelta(minutes=70)
for k in range(3):
    A(t + timedelta(seconds=25 * k), f"sshd[{pid()}]: Failed password for priya from 10.0.0.15 port 50111 ssh2")
A(t + timedelta(seconds=90), f"sshd[{pid()}]: Accepted password for priya from 10.0.0.15 port 50112 ssh2")

# admins doing normal admin things with sudo (including an interactive root shell)
for u, cmd in [("sanjay", "/usr/bin/apt update"), ("priya", "/bin/systemctl restart nginx"),
               ("sanjay", "/bin/bash"), ("sanjay", "/usr/bin/tail -f /var/log/syslog")]:
    t = T0 + timedelta(minutes=random.randint(10, 230))
    A(t, f"sudo: {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}")

# sanjay edits his own crontab (legit)
A(T0 + timedelta(minutes=95), f"crontab[{pid()}]: (sanjay) REPLACE (sanjay)")

# random internet background noise on the firewall (a few ports only)
for i in range(30):
    t = T0 + timedelta(seconds=random.randint(0, 14400))
    ip = f"{random.choice([45, 80, 92, 141, 185])}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
    for p in random.sample([22, 23, 80, 443, 3389, 5900], random.randint(1, 3)):
        tt = t + timedelta(seconds=random.randint(0, 20))
        fw.append((tt, f"{sys_ts(tt)} firewall kernel: DROP IN=eth0 SRC={ip} DST=10.0.0.5 PROTO=TCP SPT={random.randint(1024, 65000)} DPT={p}"))

# normal web traffic
for i in range(200):
    t = T0 + timedelta(seconds=random.randint(0, 14400))
    ip = f"10.0.1.{random.randint(10, 80)}"
    p = random.choice(["/", "/login", "/products?id=%d" % random.randint(1, 50), "/about", "/static/app.js"])
    web.append((t, f'{ip} - - [{web_ts(t)}] "GET {p} HTTP/1.1" 200 {random.randint(300, 8000)} "-" "Mozilla/5.0"'))

# ------------------------------------------------------------------
# SIMULATED ATTACKS  (each one is logged in ground_truth.json)
# ------------------------------------------------------------------
ATT_IP = "198.51.100.23"


def gt(aid, name, technique, rule, key, t):
    truth.append({"id": aid, "name": name, "technique": technique,
                  "expected_rule": rule, "key": key, "time": t.strftime("%H:%M:%S")})


# A1: fast SSH brute force
t = T0 + timedelta(hours=1, minutes=30)
for k in range(40):
    u = random.choice(["root", "admin", "ubuntu", "test", "oracle"])
    inv = "" if u == "root" else "invalid user "
    A(t + timedelta(seconds=3 * k), f"sshd[{pid()}]: Failed password for {inv}{u} from {ATT_IP} port {random.randint(30000, 60000)} ssh2")
gt("A1", "SSH brute force (fast)", "T1110.001", "ssh_bruteforce", ATT_IP, t)

# A2: attacker guesses the 'admin' password
t2 = t + timedelta(seconds=3 * 40 + 8)
A(t2, f"sshd[{pid()}]: Accepted password for admin from {ATT_IP} port 41022 ssh2")
gt("A2", "Valid account login after failures", "T1078", "success_after_bruteforce", ATT_IP, t2)

# A3: persistence - new local user
t3 = t2 + timedelta(minutes=2)
A(t3 - timedelta(seconds=5), "sudo: admin : TTY=pts/2 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/sbin/useradd svc_backup")
A(t3, f"useradd[{pid()}]: new user: name=svc_backup, UID=1005, GID=1005, home=/home/svc_backup, shell=/bin/bash")
gt("A3", "Backdoor user created", "T1136.001", "new_user_created", "svc_backup", t3)

# A4: new user gets a root shell through sudo
t4 = t3 + timedelta(minutes=3)
A(t4, "sudo: svc_backup : TTY=pts/3 ; PWD=/home/svc_backup ; USER=root ; COMMAND=/bin/bash")
gt("A4", "Root shell via sudo", "T1548.003", "sudo_root_shell", "svc_backup", t4)

# A5: cron persistence
t5 = t4 + timedelta(minutes=4)
A(t5, f"crontab[{pid()}]: (svc_backup) REPLACE (svc_backup)")
gt("A5", "Cron job persistence", "T1053.003", "crontab_modified", "svc_backup", t5)

# A6: LOW-AND-SLOW brute force - one try every ~5 minutes for an hour
SLOW_IP = "203.0.113.99"
t = T0 + timedelta(hours=2)
for k in range(12):
    A(t + timedelta(minutes=5 * k, seconds=random.randint(0, 40)),
      f"sshd[{pid()}]: Failed password for invalid user {random.choice(['git', 'ftp', 'postgres', 'jenkins'])} from {SLOW_IP} port {random.randint(30000, 60000)} ssh2")
gt("A6", "SSH brute force (low and slow)", "T1110.001", "ssh_bruteforce_slow", SLOW_IP, t)

# A7: port scan against the firewall
SCAN_IP = "198.51.100.77"
t = T0 + timedelta(hours=2, minutes=40)
for k, p in enumerate(random.sample(range(20, 1100), 40)):
    tt = t + timedelta(milliseconds=250 * k)
    fw.append((tt, f"{sys_ts(tt)} firewall kernel: DROP IN=eth0 SRC={SCAN_IP} DST=10.0.0.5 PROTO=TCP SPT=44{k:03d} DPT={p}"))
gt("A7", "TCP port scan", "T1046", "port_scan", SCAN_IP, t)

# A8: SQL injection against the web target
SQL_IP = "192.0.2.44"
t = T0 + timedelta(hours=3, minutes=10)
for k, p in enumerate(["/products?id=1'%20OR%20'1'='1", "/products?id=1%20UNION%20SELECT%20user,pass%20FROM%20users--",
                       "/products?id=1;%20DROP%20TABLE%20users--"]):
    tt = t + timedelta(seconds=9 * k)
    web.append((tt, f'{SQL_IP} - - [{web_ts(tt)}] "GET {p} HTTP/1.1" 500 310 "-" "curl/8.4.0"'))
gt("A8", "SQL injection", "T1190", "web_sqli", SQL_IP, t)

for name, data in (("auth.log", auth), ("firewall.log", fw), ("access.log", web)):
    data.sort(key=lambda x: x[0])
    open(name, "w").write("\n".join(l for _, l in data) + "\n")
json.dump(truth, open("ground_truth.json", "w"), indent=2)
print(f"auth {len(auth)} lines | firewall {len(fw)} | web {len(web)} | {len(truth)} simulated attacks")
