# CodeQL CLI availability and download attempt

- `codeql version`: failed, `/bin/bash: codeql: command not found`.
- Latest official CodeQL Bundle identified on GitHub Releases: v2.27.4 (2026-11-02), Linux x64 bundle. The official setup documentation recommends using the bundle, which includes the CLI and C/C++ query packs. The bundle’s download may imply agreement to GitHub CodeQL Terms and Conditions; documentation says the CLI is free for public repositories.
- Available disk: `/mnt/d` 76 GiB free; `/tmp` 939 GiB free (`df -h` output recorded in `00_baseline_and_freeze/BASELINE_QUICKCHECK.txt`).
- Attempted official HTTPS HEAD request: `curl -I -L --max-time 20 -sS https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.4/codeql-bundle-linux64.tar.zst`.
- Result: `curl: (6) Could not resolve host: github.com`. Network DNS from the sandbox is unavailable, so the official artifact and checksum could not be fetched or verified. No download/install or package installation was performed.
- Status for all six source/database analyses: `NOT_EVALUABLE`; no CodeQL query packs were available locally. Default/security-extended query contents and IDs were therefore not enumerated locally, and no negative result is inferred.

Official references (accessed 2026-11-06):
- https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.27.4
- https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli
- https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/c-cpp-built-in-queries
