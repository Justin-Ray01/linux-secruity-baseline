# linux-security-baseline — Design Notes

This project is a lightweight C++17 Linux baseline scanner that reports common hardening gaps using safe, read-only checks.

---

## Goals

- **Portable**: standard library only (no external dependencies)
- **Safe**: read-only checks; never modifies system config
- **Useful output**: human-readable report with clear risk labels
- **Resilient**: handles missing files / restricted permissions gracefully

---

## What the tool checks

### 1) File permissions — World-writable paths

**Method:**
- Recursively scans selected roots (default: `/etc`, `/var/log`, `/home`)
- Flags anything with the **others-write** permission bit (o+w)

**Notes:**
- Uses `std::filesystem` with `skip_permission_denied` to avoid crashing on protected paths
- Skips symlinks to prevent loops and unexpected traversal

---

### 2) SSH configuration — Basic hardening checks


**Inputs:**
- `/etc/ssh/sshd_config`

**Rules flagged as RISK:**
- `PermitRootLogin yes`
- `PasswordAuthentication yes`
- `PermitEmptyPasswords yes`

**Graceful behavior:**
- If SSH is not installed or access is restricted, the tool reports why instead of assuming insecure defaults.

---

### 3) Password policy — login.defs sanity checks


**Inputs:**
- `/etc/login.defs`

**Settings evaluated:**
- `PASS_MIN_LEN` (recommend >= 12)
- `PASS_MAX_DAYS` (recommend ~90 or organization standard)

**Output labels:**
- `[OK]` looks strong
- `[CHECK]` acceptable but could be improved
- `[RISK]` likely weak for a baseline
- `[UNKNOWN]` setting not found or not parseable

---

## Threat model (practical baseline)

This tool helps identify “low-hanging fruit” issues commonly leveraged in:
- brute-force / password spraying
- misconfiguration exploitation
- privilege escalation via weak permissions
- persistence via insecure remote access configuration

It is not a full vulnerability scanner and does not attempt exploitation.

---

## Limitations

- Focuses on common, high-signal checks rather than exhaustive coverage
- SSH analysis relies on file readability and common config formats
- Password policy evaluation is heuristic (baseline guidance, not compliance enforcement)

---

## Future roadmap

- JSON output mode (`--json`) for automation / pipelines
- CSV output mode for reporting
- Additional checks:
  - risky services (telnet/ftp/rsh)
  - basic kernel/sysctl hardening signals
  - user account checks (UID 0 users, locked accounts)
- Improved CLI options:
  - `--roots` custom scan roots
  - `--out` to save report files
