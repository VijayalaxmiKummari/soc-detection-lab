# Splunk versions of the detections

Each Python rule in `detectlab/rules.py` is written here as a Splunk search (SPL), using the same thresholds.

These searches assume the logs were indexed with Splunk's standard source types: `linux_secure` for auth.log and `access_combined` for the web access log. Change `index=main` to wherever your data lives.

> The Python rules are covered by unit tests. These SPL searches are translations of the same logic and have not been run against a live Splunk instance as part of this project.

## DL-001 SSH brute force against one account (T1110.001)

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bin _time span=2m
| stats count by _time, src_ip, user
| where count >= 5
```

## DL-002 SSH password spraying (T1110.003)

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bin _time span=10m
| stats dc(user) as usernames, values(user) as tried by _time, src_ip
| where usernames >= 5
```

## DL-003 Successful SSH login after repeated failures (T1078)

```spl
index=main sourcetype=linux_secure ("Failed password" OR "Accepted")
| rex "(?<action>Failed|Accepted) \S+ for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bin _time span=10m
| stats count(eval(action="Failed")) as failures,
        count(eval(action="Accepted")) as successes,
        values(user) as users by _time, src_ip
| where failures >= 5 AND successes >= 1
```

## DL-004 Sudo attempt by a user who is not allowed (T1548.003)

```spl
index=main sourcetype=linux_secure "user NOT in sudoers"
| rex "sudo:\s+(?<user>\S+) : user NOT in sudoers .*COMMAND=(?<command>.*)"
| table _time, host, user, command
```

## DL-005 New local account created (T1136.001)

```spl
index=main sourcetype=linux_secure "new user: name="
| rex "new user: name=(?<new_user>[^,]+)"
| table _time, host, new_user
```

## DL-006 SQL injection attempt (T1190)

```spl
index=main sourcetype=access_combined
| eval decoded=lower(urldecode(uri))
| where match(decoded, "union\s+(all\s+)?select|information_schema|sleep\s*\(\s*\d+\s*\)|'\s*or\s+'?\d+'?\s*=\s*'?\d+")
| stats count, values(uri) as requests by clientip
```

## DL-007 Path traversal attempt (T1190)

```spl
index=main sourcetype=access_combined
| eval decoded=lower(urldecode(urldecode(uri)))
| where match(decoded, "\.\./|/etc/passwd|/etc/shadow")
| stats count, values(uri) as requests by clientip
```

## DL-008 Known scanning tool user agent (T1595.002)

```spl
index=main sourcetype=access_combined
| where match(lower(useragent), "sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|masscan|nuclei|ffuf")
| stats count, values(useragent) as agents by clientip
```

## DL-009 Web directory enumeration (T1595.003)

```spl
index=main sourcetype=access_combined status=404
| bin _time span=1m
| stats count, dc(uri_path) as different_paths by _time, clientip
| where count >= 20
```

## A note on the time windows

`bin _time span=...` cuts time into fixed blocks, so a burst that straddles two blocks can be split and missed. The Python rules use a sliding window, which does not have that gap. In Splunk the same effect needs `streamstats time_window=2m count by src_ip, user` in place of `bin` and `stats`.
