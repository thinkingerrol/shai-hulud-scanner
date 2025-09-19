# Shai-Hulud Scanner

## Overview

The Shai-Hulud worm is a self-replicating supply chain attack that compromises npm packages by injecting malicious code during post-installation. This scanner detects infections by checking for known compromised packages, malicious files, and suspicious indicators.

## What is Shai-Hulud?

On September 14, 2025, Shai-Hulud—a self-replicating npm worm (malicious code that propagates itself automatically, infecting new targets without direct human intervention)—burst onto the scene by compromising over 180 popular packages in the registry; adversaries began by phishing maintainer accounts, then released tainted versions containing heavily obfuscated JavaScript (notably a monolithic `bundle.js`) that executed during the `postinstall` phase of `npm install`, after which the payload ran TruffleHog to hunt for secrets in the developer’s environment, double-base64-encoded the stolen data for stealth and exfiltrated it to attacker-controlled endpoints, and finally amplified its reach by republishing additional owned packages and even flipping private GitHub repositories to public via “-migration” forks.

Sources:

* [https://flyingduck.io/blogs/ctrl-tinycolor-Supply-Chain-Attack](https://flyingduck.io/blogs/ctrl-tinycolor-Supply-Chain-Attack)
* [https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)

## What is Shai-Hulud-Scanner?


**Shai-Hulud Scanner is a fast, open-source CLI tool I developed to help developers and security teams detect and mitigate the Shai-Hulud npm worm. Motivated by the worm's rapid spread and impact on the npm ecosystem, I created this scanner to provide proactive threat detection using an up-to-date affected list of compromised packages, file checks, git history analysis, and GitHub integration. It's free, community-driven, and designed to keep projects safe from supply chain attacks.**

## Features

- **Dependency Scanning**: Checks package.json and lockfiles against known compromised packages
- **File Analysis**: Detects malicious bundle.js files using SHA-256 hash verification
- **IOC Detection**: Identifies suspicious indicators of compromise
- **Git Repository Analysis**: Scans local git history for suspicious commits and branches
- **GitHub Integration**: Optional organization scanning for malicious repositories
- **Multi-format Support**: Works with npm, Yarn, and PNPM lockfiles
- **Automated Remediation**: Optional automatic cleanup of infected dependencies
- **JSON Output**: Machine-readable results for CI/CD integration

## Installation

### Local Development
```bash
git clone https://github.com/Amruth-SV/shai-hulud-scanner.git
cd shai-hulud-scanner
pip install -r requirements.txt
pip install -e .
```

## Usage

### Basic Commands

```bash
# Scan current directory
shai-hulud-scanner

# Scan specific directory
shai-hulud-scanner --dir /path/to/project

# Scan with automatic remediation
shai-hulud-scanner --remediate

# Output results as JSON
shai-hulud-scanner --json

# Show overview of Shai-Hulud worm
shai-hulud-scanner --overview
```

### Advanced Options

```bash
# Skip local git repository scan
shai-hulud-scanner --skip-git

# GitHub organization scan (optional, requires PAT)
shai-hulud-scanner --github-token ghp_xxxxx --org myorg

# Scan for secrets (shows what worm would steal)
shai-hulud-scanner --scan-secrets

# Scan GitHub Actions workflows
shai-hulud-scanner --scan-workflows

# Verbose output
shai-hulud-scanner --verbose
```

### CLI Reference

| Option | Description |
|--------|-------------|
| `-d, --dir <path>` | Directory to scan (default: current directory) |
| `-g, --github-token <token>` | GitHub token for org scan (optional) |
| `-o, --org <org>` | GitHub organization to scan (requires token) |
| `--skip-git` | Skip local git repository analysis |
| `--remediate` | Automatically uninstall bad dependencies |
| `--scan-secrets` | Scan for exposed secrets (TruffleHog simulation) |
| `--scan-workflows` | Scan GitHub Actions workflows for malicious patterns |
| `--json` | Output results as JSON |
| `--verbose` | Enable detailed logging |
| `--overview` | Display overview of Shai-Hulud worm |
| `--version` | Show version information |
| `--help` | Display help information |


## Remediation Steps

When issues are detected:

1. **Rotate Credentials**: Immediately rotate all tokens (npm, GitHub, AWS, etc.)
2. **Remove Bad Packages**: Use `--remediate` flag or manually uninstall
3. **Clean Install**: Remove node_modules and reinstall dependencies
4. **Verify**: Re-run scanner to confirm cleanup
5. **Monitor**: Check recent commits and access logs for unauthorized changes



## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make changes and test functionality
4. Test the scanner (`python -m src.cli`)
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/Amruth-SV/shai-hulud-scanner.git
cd shai-hulud-scanner
pip install -r requirements.txt
pip install -e .
python -m src.cli --help
```

## Community

Researchers, please help update the affected-packages.json with new compromised packages to keep the community safe from Shai-Hulud and similar threats. Submit PRs with reliable sources for additions—we review and merge quickly to protect everyone!


## Support

- **Issues**: [GitHub Issues](https://github.com/Amruth-SV/shai-hulud-scanner/issues)
- **Documentation**: [Wiki](https://github.com/Amruth-SV/shai-hulud-scanner/wiki)
- **Updates**: Follow releases for latest threat intelligence

## Author

**Amruth** - [GitHub](https://github.com/Amruth-SV) - [CloudSEK](https://cloudsek.com)

**Gokul peetu**