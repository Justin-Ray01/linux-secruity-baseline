#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

struct Finding {
    fs::path path;
    bool is_dir = false;
};

static std::string trim_copy(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

static std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool is_world_writable(const fs::file_status& st) {
    return (st.permissions() & fs::perms::others_write) != fs::perms::none;
}

static void scan_root_world_writable(const fs::path& root, std::vector<Finding>& out) {
    std::error_code ec;
    if (!fs::exists(root, ec)) return;

    fs::recursive_directory_iterator it(
        root,
        fs::directory_options::skip_permission_denied,
        ec
    );

    for (; !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;

        const fs::path p = it->path();

        fs::file_status st = fs::symlink_status(p, ec);
        if (ec) { ec.clear(); continue; }

        if (fs::is_symlink(st)) continue;

        if (is_world_writable(st)) {
            Finding f;
            f.path = p;
            f.is_dir = fs::is_directory(st);
            out.push_back(std::move(f));
        }
    }
}

static std::unordered_map<std::string, std::string> parse_kv_whitespace_file(const fs::path& path) {
    // Generic parser for "KEY  VALUE" style files (ignores comments/blank lines)
    std::unordered_map<std::string, std::string> kv;
    std::ifstream in(path);
    if (!in) return kv;

    std::string line;
    while (std::getline(in, line)) {
        auto hash_pos = line.find('#');
        if (hash_pos != std::string::npos) line = line.substr(0, hash_pos);

        line = trim_copy(line);
        if (line.empty()) continue;

        size_t sp = line.find_first_of(" \t");
        if (sp == std::string::npos) continue;

        std::string key = to_lower_copy(trim_copy(line.substr(0, sp)));
        std::string val = to_lower_copy(trim_copy(line.substr(sp + 1)));

        if (!key.empty() && !val.empty()) kv[key] = val; 
    }
    return kv;
}

static void print_header() {
    std::cout << "Linux Security Baseline Report\n";
    std::cout << "==============================\n\n";
}

static void print_permissions_section(const std::vector<fs::path>& roots,
                                      const std::vector<Finding>& findings) {
    std::cout << "[File Permissions] World-writable paths scan\n";
    std::cout << "Scanned roots:\n";
    for (const auto& r : roots) {
        std::cout << "  - " << r.string() << "\n";
    }
    std::cout << "\n";

    if (findings.empty()) {
        std::cout << "[OK] No world-writable files/directories found in the scanned roots.\n";
        return;
    }

    std::cout << "[!] RISK: World-writable paths found: " << findings.size() << "\n";
    for (const auto& f : findings) {
        std::cout << "  - " << (f.is_dir ? "[DIR]  " : "[FILE] ") << f.path.string() << "\n";
    }

    std::cout << "\nRecommendation:\n";
    std::cout << "  Review these paths and remove world-write permission where possible (chmod o-w ...).\n";
}

static void print_ssh_section() {
    const fs::path cfg = "/etc/ssh/sshd_config";
    std::cout << "\n[SSH Configuration] Basic hardening checks\n";

    std::error_code ec;
    bool ssh_dir_exists = fs::exists("/etc/ssh", ec);

    std::ifstream test(cfg);
    if (!test) {
    
        if (!ssh_dir_exists) {
            std::cout << "[!] /etc/ssh not found. SSH server may not be installed on this system.\n";
        } else {
            std::cout << "[!] Could not read " << cfg.string() << ".\n";
            std::cout << "    Likely causes: ssh-server not installed, file does not exist, or permissions restricted.\n";
        }
        return;
    }
    test.close();

    auto kv = parse_kv_whitespace_file(cfg);
    if (kv.empty()) {
        std::cout << "[!] " << cfg.string() << " was readable, but no settings were parsed.\n";
        return;
    }

    auto get = [&](const std::string& key) -> std::string {
        auto it = kv.find(key);
        return (it == kv.end()) ? "unknown" : it->second;
    };

    struct Rule {
        std::string key;
        std::string risky_value;
        std::string ok_hint;
        std::string why;
    };

    const std::vector<Rule> rules = {
        {"permitrootlogin", "yes",
         "Prefer: no (or prohibit-password)",
         "Root SSH login increases impact of brute-force attempts."},

        {"passwordauthentication", "yes",
         "Prefer: no (use SSH keys)",
         "Password authentication increases brute-force risk."},

        {"permitemptypasswords", "yes",
         "Prefer: no",
         "Empty passwords should never be allowed."}
    };

    int risk_count = 0;

    for (const auto& r : rules) {
        std::string v = get(r.key);

        bool is_risk = (v == r.risky_value);
        bool is_unknown = (v == "unknown");

        std::cout << "  - " << r.key << ": " << v;

        if (is_risk) {
            std::cout << "  [RISK]\n";
            std::cout << "      Why: " << r.why << "\n";
            std::cout << "      Fix: " << r.ok_hint << "\n";
            risk_count++;
        } else if (is_unknown) {
            std::cout << "  [UNKNOWN]\n";
            std::cout << "      Note: Setting not present; system defaults may apply.\n";
        } else {
            std::cout << "  [OK]\n";
        }
    }

    std::cout << "\nSSH Risk Summary: " << (risk_count == 0 ? "LOW" : "CHECK SETTINGS") << "\n";
}

static void print_password_policy_section() {
    const fs::path login_defs = "/etc/login.defs";
    std::cout << "\n[Password Policy] login.defs sanity checks\n";

    std::ifstream test(login_defs);
    if (!test) {
        std::cout << "[!] Could not read " << login_defs.string()
                  << " (file missing or permissions restricted).\n";
        return;
    }
    test.close();

    auto kv = parse_kv_whitespace_file(login_defs);
    if (kv.empty()) {
        std::cout << "[!] " << login_defs.string() << " was readable, but no settings were parsed.\n";
        return;
    }

    auto get = [&](const std::string& key) -> std::string {
        auto it = kv.find(to_lower_copy(key));
        return (it == kv.end()) ? "unknown" : it->second;
    };

    std::string min_len = get("PASS_MIN_LEN");
    std::string max_days = get("PASS_MAX_DAYS");

    // Interpret PASS_MIN_LEN
    std::cout << "  - PASS_MIN_LEN: " << min_len;
    if (min_len == "unknown") {
        std::cout << "  [UNKNOWN]\n";
    } else {
        // >= 12 ideal, 8 ok-ish, < 8 weak
        int v = 0;
        try { v = std::stoi(min_len); } catch (...) { v = -1; }

        if (v >= 12) std::cout << "  [OK]\n";
        else if (v >= 8) std::cout << "  [CHECK]\n";
        else if (v >= 0) std::cout << "  [RISK]\n";
        else std::cout << "  [UNKNOWN]\n";
    }

    // Interpret PASS_MAX_DAYS
    std::cout << "  - PASS_MAX_DAYS: " << max_days;
    if (max_days == "unknown") {
        std::cout << "  [UNKNOWN]\n";
    } else {
        int v = 0;
        try { v = std::stoi(max_days); } catch (...) { v = -1; }

        //  <= 90 good, 91-180 okay, very large values often mean "never expires"
        if (v > 0 && v <= 90) std::cout << "  [OK]\n";
        else if (v > 90 && v <= 180) std::cout << "  [CHECK]\n";
        else if (v > 180) std::cout << "  [RISK]\n";
        else std::cout << "  [UNKNOWN]\n";
    }

    std::cout << "\nRecommendations:\n";
    std::cout << "  - Prefer PASS_MIN_LEN >= 12 for stronger baseline policy.\n";
    std::cout << "  - Prefer PASS_MAX_DAYS around 90 (or organization standard).\n";
}

int main(int argc, char* argv[]) {
    // Default scan roots. Override by passing directories:
    // ./baseline /etc /var/log
    std::vector<fs::path> roots = {"/etc", "/var/log", "/home"};
    if (argc > 1) {
        roots.clear();
        for (int i = 1; i < argc; i++) roots.emplace_back(argv[i]);
    }

    std::vector<Finding> findings;
    findings.reserve(128);

    for (const auto& r : roots) {
        scan_root_world_writable(r, findings);
    }

    print_header();
    print_permissions_section(roots, findings);
    print_ssh_section();
    print_password_policy_section();

    std::cout << "\nDone.\n";
    return 0;
}
