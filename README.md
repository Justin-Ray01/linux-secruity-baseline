# linux-security-baseline

A lightweight **C++17** command-line tool that audits a Linux system’s basic security posture and prints a clean, human-readable report.

This project complements my `cpp-log-analyzer` repo by focusing on **prevention/hardening** rather than detection.

---

## What it checks

- **World-writable paths** (misconfiguration risk)
- **SSH hardening signals** from `/etc/ssh/sshd_config` (when available)
- **Password policy signals** from `/etc/login.defs`

The tool is designed to run safely in restricted environments (school VMs/lab images) without requiring root.

---

##Eample Output

<img width="977" height="561" alt="linux-security-baseline2" src="https://github.com/user-attachments/assets/2fd63928-693b-4e5e-a14b-c308c0545efc" />


