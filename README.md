# cybertek-threat-intel

Automated daily aggregation of public threat intelligence blocklists, maintained by [cybertek605](https://github.com/cybertek605).

Lists are updated daily at **02:00 UTC** via GitHub Actions and consumed by the Cybertek Syncro Network Traffic Monitor.

---

## Output Files

| File | Type | Description |
|---|---|---|
| `lists/ip_blocklist.txt` | IPv4 addresses | All unique IPs from all sources (flat list) |
| `lists/ip_scores.txt` | Scored IPv4 addresses | `score<TAB>ip` — score = number of source feeds containing this IP |
| `lists/cidr_blocklist.txt` | CIDR ranges | Spamhaus DROP + EDROP |
| `lists/domain_blocklist.txt` | Hostnames | URLhaus malware distribution domains |
| `lists/metadata.json` | Stats | Source counts, last-updated timestamp, max score |

---

## Scoring System

Each IP source contributes **1 point** to an IP's score. An IP seen across multiple independent feeds has a higher score, indicating broader cross-feed consensus on maliciousness.

```
score 1   → single source flagged     → Warning  alert in Syncro
score 2+  → multiple sources agree    → Critical alert in Syncro
```

`ip_scores.txt` is sorted by score descending so the highest-confidence IPs appear first.

---

## Sources

### IP Sources (contribute to scoring)

| Source | Feed | Score Weight |
|---|---|---|
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 servers (Emotet, TrickBot, QakBot, Dridex) | 1 point |
| [Emerging Threats](https://rules.emergingthreats.net/) | Broadly compromised / malicious IPs | 1 point |
| [CINS Army](http://cinsscore.com/) | Active threat actors, scanners, brute-force sources | 1 point |
| [Binary Defense](https://www.binarydefense.com/) | Artillery threat intelligence feed | 1 point |
| [Greensnow](https://blocklist.greensnow.co/) | General attack / scanner IPs | 1 point |
| [Tor Exit Nodes](https://check.torproject.org/) | All current Tor exit nodes | 1 point |
| [Abuse.ch SSLBL](https://sslbl.abuse.ch/) | IPs with malicious SSL certificates / C2 traffic | 1 point |
| [ThreatFox](https://threatfox.abuse.ch/) | Recent IOCs from the abuse.ch database | 1 point |
| [IPsum](https://github.com/stamparm/ipsum) | Meta-aggregator (~30 feeds); included when IPsum score >= 3 | 1 point |

### CIDR Sources

| Source | Feed |
|---|---|
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | IP ranges operated by professional crime gangs |
| [Spamhaus EDROP](https://www.spamhaus.org/drop/) | Extended DROP — hijacked netblocks |

### Domain Sources

| Source | Feed |
|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) | Malware distribution domains |

---

## Raw URLs

```
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/ip_blocklist.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/ip_scores.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/cidr_blocklist.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/domain_blocklist.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/metadata.json
```

---

## Notes

- **Spamhaus DROP/EDROP** are free for non-commercial use. See [Spamhaus usage terms](https://www.spamhaus.org/organization/dnsblusage/) for commercial contexts.
- **IPsum** is a community-maintained meta-aggregator. Using it as one of nine sources prevents it from dominating the score while still benefiting from its breadth.
- The maximum possible score for any IP is **9** (present in all nine IP source feeds).
