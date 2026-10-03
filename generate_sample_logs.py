"""
generate_sample_logs.py - write the two sample log files in sample_logs/.

The logs describe one made-up day on a small web server called web01. They mix
ordinary activity with a handful of attacks so every detection rule has
something to find, and so there is normal traffic the rules must NOT flag.

All "attacker" addresses come from the ranges reserved for documentation
(203.0.113.0/24 and 198.51.100.0/24), so they do not belong to anyone.

Run it again any time to rebuild the files:
    python3 generate_sample_logs.py
"""

import os
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "sample_logs")
DAY = datetime(2026, 10, 3)
BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"


def at(hour, minute, second=0):
    return DAY + timedelta(hours=hour, minutes=minute, seconds=second)


def auth(when, process, message):
    return when, "{} {:>2} {} web01 {}: {}".format(
        when.strftime("%b"), when.day, when.strftime("%H:%M:%S"), process, message)


def web(when, ip, request, status, size, agent=BROWSER):
    return when, '{} - - [{} +0000] "{}" {} {} "-" "{}"'.format(
        ip, when.strftime("%d/%b/%Y:%H:%M:%S"), request, status, size, agent)


def build_auth_log():
    lines = []

    # --- Ordinary activity -------------------------------------------------
    lines.append(auth(at(7, 58, 12), "sshd[1840]", "Accepted publickey for alice from 10.0.0.21 port 50212 ssh2"))
    lines.append(auth(at(7, 58, 12), "sshd[1840]", "pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)"))
    lines.append(auth(at(8, 4, 40), "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"))
    # bob mistypes his password twice, then gets in. Two failures must not raise an alert.
    lines.append(auth(at(8, 31, 2), "sshd[1902]", "Failed password for bob from 10.0.0.34 port 51877 ssh2"))
    lines.append(auth(at(8, 31, 9), "sshd[1902]", "Failed password for bob from 10.0.0.34 port 51877 ssh2"))
    lines.append(auth(at(8, 31, 20), "sshd[1902]", "Accepted password for bob from 10.0.0.34 port 51877 ssh2"))
    for hour in range(8, 17):
        lines.append(auth(at(hour, 17, 1), "CRON[{}]".format(2000 + hour),
                          "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
        lines.append(auth(at(hour, 17, 1), "CRON[{}]".format(2000 + hour),
                          "pam_unix(cron:session): session closed for user root"))

    # --- Attack 1: brute force against root (8 tries in 40 seconds) ---------
    for i in range(8):
        lines.append(auth(at(9, 12, i * 5), "sshd[{}]".format(2211 + i),
                          "Failed password for root from 203.0.113.50 port {} ssh2".format(40112 + i)))

    # --- Attack 2: password spraying (one try each against 7 usernames) -----
    for i, name in enumerate(["admin", "test", "oracle", "postgres", "ubuntu", "guest", "ftpuser"]):
        lines.append(auth(at(10, 30, i * 25), "sshd[{}]".format(2540 + i),
                          "Failed password for invalid user {} from 203.0.113.61 port {} ssh2".format(name, 38800 + i)))

    # --- Attack 3: the password for 'deploy' is guessed ---------------------
    for i in range(6):
        lines.append(auth(at(11, 2, i * 9), "sshd[{}]".format(2790 + i),
                          "Failed password for deploy from 203.0.113.88 port {} ssh2".format(44020 + i)))
    lines.append(auth(at(11, 3, 10), "sshd[2797]", "Accepted password for deploy from 203.0.113.88 port 44031 ssh2"))
    lines.append(auth(at(11, 3, 10), "sshd[2797]", "pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0)"))
    # ... and the intruder immediately tries to become root.
    lines.append(auth(at(11, 5, 44), "sudo", "  deploy : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"))

    # --- A new account appears in the afternoon -----------------------------
    lines.append(auth(at(14, 40, 3), "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m sysbackup"))
    lines.append(auth(at(14, 40, 3), "useradd[3120]", "new user: name=sysbackup, UID=1004, GID=1004, home=/home/sysbackup, shell=/bin/sh, from=/dev/pts/0"))

    return [line for _, line in sorted(lines, key=lambda pair: pair[0])]


def build_access_log():
    lines = []

    # --- Ordinary visitors --------------------------------------------------
    pages = [("/", 200, 5120), ("/products", 200, 8344), ("/products?id=12", 200, 4102),
             ("/static/css/site.css", 200, 1820), ("/static/js/app.js", 200, 9210),
             ("/about", 200, 3011), ("/contact", 200, 2750), ("/favicon.ico", 404, 162)]
    visitors = ["198.51.100.14", "198.51.100.27", "198.51.100.63", "198.51.100.91", "10.0.0.21"]
    for n in range(72):
        page, status, size = pages[n % len(pages)]
        lines.append(web(at(8 + n // 9, (n * 7) % 60, (n * 13) % 60),
                         visitors[n % len(visitors)], "GET {} HTTP/1.1".format(page), status, size))

    # --- Attack 4: SQL injection with sqlmap --------------------------------
    payloads = ["/products.php?id=1%27%20OR%20%271%27%3D%271",
                "/products.php?id=1%20UNION%20SELECT%20NULL%2Cusername%2Cpassword%20FROM%20users--",
                "/products.php?id=1%20UNION%20ALL%20SELECT%20table_name%20FROM%20information_schema.tables",
                "/products.php?id=1%20AND%20SLEEP(5)",
                "/products.php?id=1%27%3B%20DROP%20TABLE%20users--",
                "/products.php?id=1"]
    for i, payload in enumerate(payloads):
        lines.append(web(at(9, 30, 2 + i * 3), "203.0.113.77", "GET {} HTTP/1.1".format(payload),
                         200 if i == 5 else 500, 512, "sqlmap/1.7.11#stable (https://sqlmap.org)"))

    # --- Attack 5: path traversal -------------------------------------------
    for i, target in enumerate(["/download?file=../../../../etc/passwd",
                                "/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                                "/download?file=..%252f..%252f..%252fetc%252fshadow"]):
        lines.append(web(at(12, 10, 5 + i * 11), "203.0.113.90", "GET {} HTTP/1.1".format(target),
                         400, 226, "curl/8.4.0"))

    # --- Attack 6: directory enumeration (30 guesses in 30 seconds) ---------
    words = ["admin", "backup", "config", "db", "old", "test", "dev", "staging", "private", "secret",
             "uploads", "includes", "phpmyadmin", "wp-admin", "wp-login.php", ".git/config", ".env",
             "server-status", "api", "console", "dashboard", "login", "portal", "tmp", "logs",
             "dump.sql", "backup.zip", "site.tar.gz", "cgi-bin", "shell.php"]
    for i, word in enumerate(words):
        status = {"login": 200, "server-status": 403}.get(word, 404)
        lines.append(web(at(13, 45, i), "203.0.113.120", "GET /{} HTTP/1.1".format(word), status, 162))

    # --- Attack 7: a Nikto scan ---------------------------------------------
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000003)"
    for i, (path, status) in enumerate([("/", 200), ("/robots.txt", 404), ("/icons/README", 404), ("/index.php?", 200)]):
        lines.append(web(at(15, 20, 1 + i), "203.0.113.140", "GET {} HTTP/1.1".format(path), status, 300, nikto))

    return [line for _, line in sorted(lines, key=lambda pair: pair[0])]


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, lines in (("auth.log", build_auth_log()), ("access.log", build_access_log())):
        path = os.path.join(OUT_DIR, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        print("[✓] Wrote {} lines to {}".format(len(lines), path))


if __name__ == "__main__":
    main()
