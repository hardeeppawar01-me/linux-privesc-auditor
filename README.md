# Linux PrivEsc Auditor

A Linux security auditing framework designed to identify
potential privilege-escalation risks caused by insecure
system configurations.

The tool performs defensive security checks and generates
HTML and JSON assessment reports.

---

## Features

- System information enumeration
- User and group enumeration
- Sudo permission auditing
- SUID/SGID binary detection
- Linux capability detection
- Cron configuration auditing
- World-writable file detection
- Risk scoring
- Security recommendations
- HTML security reports
- JSON security reports
- Command-line interface

---

## Architecture

```text
                    Linux System
                         |
                         v
                Linux PrivEsc Auditor
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
   System/User       Privilege        File/System
   Enumeration       Checks           Checks
        |                |                |
        |         +------+-------+        |
        |         |      |       |        |
        |       Sudo   SUID   Capabilities|
        |                                |
        |                         Cron / Writable
        |                                |
        +---------------+----------------+
                        |
                        v
                  Risk Engine
                        |
                        v
              Security Findings
                        |
              +---------+---------+
              |                   |
              v                   v
         HTML Report         JSON Report

