# axios-vuln-scanner

> Scan your Node.js projects for vulnerable `axios` versions — powered by live data from the [OSV API](https://osv.dev), zero dependencies, CI-ready.

[![Node.js](https://img.shields.io/badge/node-%3E%3D14-brightgreen)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-success)
[![OSV](https://img.shields.io/badge/vulns-OSV%20API-blue)](https://osv.dev)
---

## Why?

Most projects have multiple `package.json` files — monorepos, nested apps, microservices. Finding every project that uses a vulnerable `axios` version by hand is slow and error-prone.

**axios-vuln-scanner** walks your entire directory tree, finds every project that depends on `axios`, and checks each installed version against the **OSV database** in real time — giving you up-to-date CVE data, not a hardcoded list that goes stale.

---

## Features

| | |
|---|---|
| 🔍 **Recursive scan** | Walks all subdirectories, skips `node_modules`, `.git`, `dist`, `.next` |
| 🌐 **Live vulnerability data** | Queries [OSV API](https://osv.dev) for each unique version found |
| 📦 **Checks installed version** | Reads the actual version from `node_modules/axios/package.json` |
| 🔌 **Offline fallback** | Falls back to a built-in DB if the network is unavailable |
| ⚡ **Parallel requests** | All OSV queries run concurrently — fast even with many projects |
| 🎨 **Colored output** | Instant visual triage in the terminal |
| 🚦 **Exit code 1** | Fails the build when vulnerabilities are found — perfect for CI/CD |
| 🪶 **Zero dependencies** | Pure Node.js, nothing to install |

---

## Usage

### Run directly (no install needed)

```bash
# Scan current directory
node scan.js

# Scan a specific path
node scan.js /path/to/your/projects
```

### Install globally

```bash
npm install -g axios-vuln-scanner

axios-vuln-scanner
axios-vuln-scanner /path/to/projects
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `[path]` | `.` (current directory) | Directory to scan |
| `--no-dev` | off | Ignore `devDependencies` |
| `--include-dist` | off | Also scan `dist`, `.next`, `build`, `out` |
| `--no-exit` | off | Do not exit with code 1 on vulnerabilities |
| `--offline` | off | Skip OSV API, use built-in DB only |

### Examples

```bash
# Scan a specific folder
node scan.js /home/user/projects

# Ignore devDependencies
node scan.js . --no-dev

# Also scan inside dist and .next
node scan.js . --include-dist

# Disable CI exit code
node scan.js . --no-exit

# No internet access
node scan.js . --offline

# Combine flags
node scan.js /var/www --no-dev --include-dist
```

---

## Sample Output

```
axios-vuln-scanner
Scanning     : /home/user/projects
devDeps      : included
dist/.next   : ignored
Vuln source  : OSV API (live)

Querying OSV API for 2 version(s)...

────────────────────────────────────────────────────
Project   : my-api-server  ✖ VULNERABLE
Path      : /home/user/projects/my-api-server/package.json
Declared  : ^1.4.0
Installed : 1.4.0
  ⚠  CVE-2023-45857 [HIGH]
     Cross-Site Request Forgery via forged headers
     Fix: upgrade axios to >= 1.6.0

────────────────────────────────────────────────────
Project   : frontend-app  ✔ OK
Path      : /home/user/projects/frontend-app/package.json
Declared  : ^1.7.2
Installed : 1.7.2

────────────────────────────────────────────────────

Summary: 2 project(s) — 1 vulnerable, 1 safe
```

---

## How It Works

```
scan(directory)
    │
    ├── Collect all package.json files
    │       └── Skip: node_modules / .git / dist / .next
    │
    ├── Extract unique installed axios versions
    │
    ├── Query OSV API in parallel (one request per unique version)
    │       └── Fallback to offline DB if network fails
    │
    └── Print results + exit code 1 if any vulnerabilities found
```

### OSV API request format

For each unique installed version, the scanner sends:

```json
POST https://api.osv.dev/v1/query

{
  "version": "1.4.0",
  "package": {
    "name": "axios",
    "ecosystem": "npm"
  }
}
```

OSV returns all known vulnerabilities for that exact version — CVE IDs, severity, description, and the fixed version.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan for vulnerable axios
  run: node scan.js .
  # Exits with code 1 if vulnerabilities are found
```

### npm script

```json
{
  "scripts": {
    "security:axios": "node scan.js ."
  }
}
```

---

## Offline Mode

If you're running in an air-gapped environment or want deterministic results without network calls:

```bash
node scan.js . --offline
```

The built-in database currently covers:

| CVE | Severity | Affected | Fixed |
|-----|----------|----------|-------|
| [CVE-2023-45857](https://nvd.nist.gov/vuln/detail/CVE-2023-45857) | HIGH | `< 0.28.0` and `1.x < 1.6.0` | `0.28.0` / `1.6.0` |

For the most complete and up-to-date coverage, always use the default live mode.

---

## Contributing

Pull requests are welcome. To add a vulnerability to the offline fallback DB, update `OFFLINE_DB` in `scan.js`:

```js
const OFFLINE_DB = [
  {
    cve: "CVE-XXXX-XXXXX",
    severity: "HIGH",
    summary: "Short description",
    fixed: "X.Y.Z",
    affects: (v) => isBelow(v, "X.Y.Z"),
  },
];
```

---

## License

[MIT](./LICENSE) © [ikhd](https://github.com/ikhd)
