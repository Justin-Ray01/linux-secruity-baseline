# Design Notes

Goal: a portable C++17 baseline scanner that runs without root and reports common hardening gaps.

Phase 1:
- Scan for world-writable files in selected directories

Future:
- Parse /etc/ssh/sshd_config for risky settings
- Parse /etc/login.defs for password policy
- Basic process/service checks
- JSON output mode
