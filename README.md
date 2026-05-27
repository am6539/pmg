<div align="center">
    <h1>Package Manager Guard (PMG)</h1>
</div>

<p align="center">
    <strong>Block malicious npm and pip packages before they install.</strong><br>
    Defense in depth for the package managers you already use.
</p>

<div align="center">
  <img src="./docs/demo/pmg-intro.gif" width="800" alt="pmg in action">
</div>

<br>

<div align="center">

![License](https://img.shields.io/github/license/am6539/pmg)
![Release](https://img.shields.io/github/v/release/am6539/pmg)
[![CodeQL](https://github.com/am6539/pmg/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/am6539/pmg/actions/workflows/codeql.yml)

</div>

## Why PMG?

Developers and AI coding agents install packages every day. Each `npm install` or `pip install` executes thousands of lines of code that nobody reviews.

Recent compromises in popular ecosystems include hijacked packages, dependency confusion, typosquats, and packages that exfiltrate developer credentials.

PMG intercepts every package install and checks it for malware **before** code executes. Install it once, and PMG covers every `npm install`, `pip install`, and `poetry add` after that.

> Featured in [tl;dr sec](https://tldrsec.com/p/tldr-sec-316).

## How PMG Works

PMG takes a defense-in-depth approach. Each install passes through multiple protection layers before code runs, plus an audit trail after.

- **Transparent Interception** — PMG wraps `npm`, `pip`, and other package managers. Developers and AI agents use the same commands with no workflow changes.
- **Layer 1: Threat Intelligence** — Checks packages against SafeDep Cloud and the [Aikido Intel](#aikido-intel-malware-feed) community feed. Known-malicious packages never reach disk.
- **Layer 2: Policy (Dependency Cooldown)** — Blocks package versions published within a configurable time window, reducing exposure to freshly-compromised releases.
- **Layer 3: Optional Sandbox** — When enabled, PMG runs installs inside OS-native sandboxes (macOS Seatbelt, Linux Landlock / Bubblewrap) so install scripts have restricted system access even if a threat slips through.
- **Audit Logging** — Every install is logged (what, when, from where) for a verifiable audit trail. Events can be synced to a self-hosted [pmg-cloud](https://github.com/am6539/pmg-cloud) backend.

## Quick Start

### 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/am6539/pmg/main/install.sh | sh
```

> This fork publishes binaries from `am6539/pmg` releases. Homebrew and npm package installs still refer to upstream SafeDep builds and are not recommended for this fork.

### 2. Setup

Wire PMG into your shell so it intercepts package managers.

```bash
pmg setup install
# Restart your terminal to apply changes
```

> **Tip:** Re-run `pmg setup install` after upgrading PMG to pick up new configuration options.

### 3. Use

Run your package managers as usual, or let your AI coding agent run them.

```bash
npm install express
pip install requests
```

PMG intercepts the command, checks every package, and blocks anything flagged as malicious.

## Features

| Feature | Description |
|---------|-------------|
| **AI Agent Safety Net** | Catches malicious packages installed by AI coding agents (Claude Code, Cursor, Copilot, Windsurf). |
| **Aikido Intel Feed** | Free community malware feed — no API key required, works offline with local disk cache. |
| **Dependency Cooldown** | Blocks package versions published within a configurable window, reducing supply-chain attack exposure. |
| **Sandbox Isolation** | OS-native sandboxes restrict what install scripts can do (macOS Seatbelt, Linux Landlock/Bubblewrap). |
| **Self-Hosted Backend** | Sync audit events to your own [pmg-cloud](https://github.com/am6539/pmg-cloud) server for centralized visibility. |
| **Zero Config** | Works out of the box with sensible security defaults. |
| **Cross-Shell** | Integrates with Zsh, Bash, Fish, and more. |

## Supported Package Managers

| Ecosystem | Tools | Command Example |
|-----------|-------|----------------|
| **Node.js** | `npm`, `pnpm`, `yarn`, `bun`, `npx`, `pnpx` | `npm install <pkg>` |
| **Python** | `pip`, `poetry`, `uv` | `pip install <pkg>` |

## Installation

<details>
<summary><strong>Install Script (macOS / Linux)</strong></summary>

Downloads the latest release from GitHub, verifies its SHA-256 checksum, and installs to `$HOME/.local/bin` (if on `PATH`) or `/usr/local/bin`.

```bash
curl -fsSL https://raw.githubusercontent.com/am6539/pmg/main/install.sh | sh
```

</details>

<details>
<summary><strong>Go (Build from Source)</strong></summary>

```bash
# Ensure $(go env GOPATH)/bin is in your $PATH
go install github.com/am6539/pmg@main
```

</details>

<details>
<summary><strong>Binary Download</strong></summary>

Download the latest binary for your platform from the [am6539/pmg Releases Page](https://github.com/am6539/pmg/releases).

</details>

## GitHub Actions

Protect CI workflows with one step. PMG analyzes every `npm install`, `pip install`, etc. in the job.

```yaml
- uses: actions/setup-node@v6
  with:
    node-version: 24
- uses: am6539/pmg@v1
- run: npm ci
```

By default you get malware blocking and dependency cooldown. Tune behavior via inputs (`paranoid`, `sandbox`, `cooldown-days`, ...) or point `config-file` at a YAML in the repo.  
See [docs/github-action.md](docs/github-action.md) for the full reference.

### Reporting to a self-hosted backend in CI

```yaml
- uses: am6539/pmg@v1
  env:
    PMG_CLOUD_ENABLED: "true"
    PMG_CLOUD_ADDR: "your-server:8443"
    PMG_CLOUD_API_KEY: ${{ secrets.PMG_API_KEY }}
    PMG_CLOUD_INSECURE: "true"              # omit if TLS is configured
    PMG_CLOUD_ENDPOINT_ID: "github-actions/${{ github.repository }}"
    PMG_CLOUD_AUTO_SYNC_ENABLED: "false"    # flush manually at job end

- run: npm ci

- name: Sync PMG events
  if: always()
  run: pmg cloud sync
```

## Aikido Intel malware feed

PMG bundles the [Aikido](https://www.aikido.dev/) community malware feed for offline-capable, no-key-required package scanning. It runs alongside SafeDep Cloud — if either source flags a package, the install is blocked.

```bash
# Pre-fetch and cache both feeds (useful in CI to warm the cache before installs)
pmg aikido refresh
```

By default the feed is cached for 1 hour and pulled from `https://malware-list.aikido.dev`. For air-gapped environments, point `base_url` at your pmg-cloud server which mirrors the feed automatically:

```yaml
# ~/.pmg/config.yml
aikido_intel:
  enabled: true
  base_url: "http://your-pmg-cloud:8080"   # self-hosted mirror
  cache_ttl: 1h
```

## Self-hosted backend (pmg-cloud)

[pmg-cloud](https://github.com/am6539/pmg-cloud) is a self-hosted gRPC + HTTP server that receives audit events from PMG agents and serves a web dashboard with per-endpoint, per-repository, and malware feed visibility.

### Enroll with one command

```bash
# On the target machine — installs PMG and configures it automatically
curl -sSfL http://your-server:8080/install.sh | sh -s -- --token=pmgenroll_xxx
```

Enrollment tokens are generated in the pmg-cloud dashboard under **Agents → Create Enrollment Token**.

### Manual enrollment

```bash
pmg cloud enroll --endpoint http://your-server:8080 --token pmgenroll_xxx
```

### Manual config

```yaml
# ~/.pmg/config.yml
cloud:
  enabled: true
  addr: "your-server:8443"
  api_key: "your-api-key"   # from pmg-cloud Groups page
  insecure: false            # true only for servers without TLS
```

## Configuration

PMG uses a YAML config file (`~/.pmg/config.yml`) generated on first run. All keys can also be overridden with `PMG_*` environment variables.

```bash
pmg config get cloud.enabled       # read a value
pmg config set cloud.enabled true  # write a value
```

Key environment variables:

| Variable | Description |
|----------|-------------|
| `PMG_CLOUD_ENABLED` | Enable cloud sync (`true`/`false`) |
| `PMG_CLOUD_ADDR` | Custom gRPC address (`host:port`) |
| `PMG_CLOUD_API_KEY` | API key for self-hosted pmg-cloud |
| `PMG_CLOUD_INSECURE` | Disable TLS — dev/self-hosted only |
| `PMG_CLOUD_ENDPOINT_ID` | Override endpoint identifier |
| `PMG_CLOUD_AUTO_SYNC_ENABLED` | Background auto-sync toggle |
| `PMG_PARANOID` | Treat suspicious packages as malicious |
| `PMG_DISABLE_TELEMETRY` | Disable anonymous usage telemetry |

## CLI reference

```
pmg setup install          Wire PMG into your shell
pmg setup remove           Remove shell integration

pmg cloud enroll           Enroll with a self-hosted pmg-cloud server
pmg cloud sync             Flush buffered audit events to the cloud backend
pmg cloud login            Store SafeDep Cloud credentials (keychain)
pmg cloud logout           Remove stored credentials

pmg aikido refresh         Pre-fetch and cache Aikido malware feeds

pmg config get <key>       Read a config value
pmg config set <key> <v>   Write a config value
```

## Uninstallation

```bash
pmg setup remove                    # remove shell integration
pmg setup remove --config-file      # also remove config file
rm -f ~/.local/bin/pmg              # remove binary (install-script default path)
# or: sudo rm -f /usr/local/bin/pmg
```

## Trust and Security

PMG builds are reproducible and signed.

- **Attestations**: GitHub and npm attestations guarantee artifact integrity.
- **Verification**: You can cryptographically prove the binary matches the source code.
- See [Trusting PMG](docs/trust.md) for verification steps.

## User Guide

- [Trusted Packages Configuration](docs/trusted-packages.md)
- [Dependency Cooldown](docs/dependency-cooldown.md)
- [Proxy Mode Architecture](docs/proxy-mode.md)
- [Sandboxing Details](docs/sandbox.md)
- [GitHub Action Reference](docs/github-action.md)

## Telemetry

PMG collects anonymous usage data. To disable:

```bash
pmg config set disable_telemetry true
# or export PMG_DISABLE_TELEMETRY=true
```

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for build and test instructions.

## Support

This fork is maintained for the `am6539/pmg` custom build.
