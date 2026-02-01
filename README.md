# linux-security-baseline

A lightweight **C++17** command-line tool that audits a Linux system’s basic security posture and prints a human-readable report.

This project complements `cpp-log-analyzer` by focusing on **prevention/hardening** instead of detection.

---

## Checks (Phase 1)
- World-writable file scan (common misconfiguration risk)
- (Coming next) SSH hardening checks (`sshd_config`)
- (Coming next) Password policy checks (`login.defs`)
- (Coming next) Basic service/process inspection

---

## Build & Run

### Linux (g++)
```bash
g++ -std=c++17 -O2 -Wall -Wextra -o baseline src/main.cpp
./baseline
