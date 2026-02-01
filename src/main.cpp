#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Finding {
    fs::path path;
    bool is_dir = false;
};

static bool is_world_writable(const fs::file_status& st) {
    // Check "others write" permission bit.
    // perms::others_write is set when chmod ... o+w.
    return (st.permissions() & fs::perms::others_write) != fs::perms::none;
}

static void scan_root(const fs::path& root, std::vector<Finding>& out) {
    std::error_code ec;

    if (!fs::exists(root, ec)) return;

    // directory_options::skip_permission_denied prevents exceptions when we lack access
    fs::recursive_directory_iterator it(
        root,
        fs::directory_options::skip_permission_denied,
        ec
    );

    for (; !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;

        const fs::path p = it->path();

        // Use symlink_status so symlinks don't surprise us.
        fs::file_status st = fs::symlink_status(p, ec);
        if (ec) { ec.clear(); continue; }

        // Skip symlinks (optional safety)
        if (fs::is_symlink(st)) continue;

        if (is_world_writable(st)) {
            Finding f;
            f.path = p;
            f.is_dir = fs::is_directory(st);
            out.push_back(std::move(f));
        }
    }
}

static void print_report(const std::vector<fs::path>& roots, const std::vector<Finding>& findings) {
    std::cout << "Linux Security Baseline Report\n";
    std::cout << "==============================\n\n";

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
        std::cout << "  - " << (f.is_dir ? "[DIR] " : "[FILE] ") << f.path.string() << "\n";
    }

    std::cout << "\nRecommendation:\n";
    std::cout << "  Review these paths and remove world-write permission where possible (chmod o-w ...).\n";
}

int main(int argc, char* argv[]) {
    // Simple defaults. Later we can add flags like --roots or --json.
    std::vector<fs::path> roots = {"/etc", "/var/log", "/home"};

    // Optional: allow passing custom roots as args:
    // ./baseline /etc /var/log
    if (argc > 1) {
        roots.clear();
        for (int i = 1; i < argc; i++) roots.emplace_back(argv[i]);
    }

    std::vector<Finding> findings;
    findings.reserve(128);

    for (const auto& r : roots) {
        scan_root(r, findings);
    }

    print_report(roots, findings);
    return 0;
}
