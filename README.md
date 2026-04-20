# Forge
[![Go Version](https://img.shields.io/github/go-mod/go-version/Jina404/forge)](https://github.com/Jina404/forge)
[![License](https://img.shields.io/github/license/Jina404/forge)](LICENSE)
[![Issues](https://img.shields.io/github/issues/Jina404/forge)](https://github.com/Jina404/forge/issues)
[![Stars](https://img.shields.io/github/stars/Jina404/forge)](https://github.com/Jina404/forge/stargazers)
**Forge** is an open-source, high-performance resilience and security testing tool. It combines massive load generation with advanced vulnerability detection to answer one critical question:

> *"Does my application stay secure when it's under attack?"*

Unlike traditional tools that test performance or security in isolation, Forge **simultaneously** floods your app with traffic and fuzzes parameters with malicious payloads. It detects both obvious vulnerabilities (like SQL errors) and **blind vulnerabilities** (time-based SQLi, subtle response differences) that only manifest under stress.

---

## Features

- **High-Concurrency Load Engine** – Generate 10,000+ requests/sec from a single laptop.
- **Advanced Vulnerability Detection** – Signature-based, time-based blind, boolean blind, and response diffing.
- **Context-Aware XSS Detection** – Identifies reflection context (script tag, attribute, JS string).
- **Resilience Correlation** – See if your WAF or rate limiter fails under load.
- **Detailed Remediation Advice** – Every finding comes with a plain-English explanation and fix.
- **Local-First, Zero Dependencies** – Single binary, no Docker, no cloud required.
- **Mixed-Mode Testing** – Simulate real users + attackers simultaneously.

---

## Installation

### Option 1: Clone and Build (Recommended)

```bash
# Clone the repository
git clone https://github.com/Jina404/forge.git
cd forge

# Build the binary (requires Go 1.20+)
go mod tidy
go build -o forge ./cmd/forge

# Move to your PATH (optional)
sudo mv forge /usr/local/bin/