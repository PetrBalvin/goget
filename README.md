# goget

[![Go Version](https://img.shields.io/badge/Go-1.20+-blue)](https://go.dev)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-green)](LICENSE)

**A modern command-line download utility written in Go with IPv6 support and wget-like features**

---

## Description
`goget` is a lightweight, cross-platform download tool inspired by `wget`, built with modern Go features and full IPv6 support. It provides a simple interface for downloading files over HTTP/HTTPS/FTP with advanced capabilities like parallel connections, recursive downloads, and persistent cookies.

---

## Features
✅ **Core Functionality**
- HTTP/HTTPS/FTP downloads with automatic protocol detection
- IPv6 support (`-6` flag)
- Recursive downloading with depth control (`-r -l=DEPTH`)
- Parallel connections for faster downloads (`-N=THREADS`)

🔒 **Authentication**
- HTTP Basic/Digest authentication (`--digest`, `-http-user`, `-http-pass`)
- FTP authentication (`-ftp-user`, `-ftp-pass`)

🍪 **Session Management**
- Persistent cookies via `--cookies=FILE`

🔍 **Advanced Options**
- File extension filtering (`-A=pdf,zip -R=jpg`)
- Domain restriction (`-D=example.com`)
- Retry mechanism (`-tries=COUNT`)
- Custom User-Agent (`-U="Custom Agent"`)

---

## Installation
### Using Go
```bash
# Install directly from source
go install github.com/petrbalvin/goget@latest

# Verify installation
goget --version

---

### Manual Build
```bash
git clone https://github.com/petrbalvin/goget.git
cd goget
go build -o goget main.go
sudo mv goget /usr/local/bin/

## Usage Examples
```bash
# Basic download
goget -url=https://example.com/file.zip -O=output.zip

# Recursive website download (depth 3)
goget -r -l=3 -url=https://example.com

# FTP download with credentials
goget -url=ftp://ftp.example.com/file.txt -ftp-user=admin -ftp-pass=secret

# Parallel download (4 threads)
goget -N=4 -url=http://ipv4.download.thinkbroadband.com/10MB.zip

# Filter by extensions
goget -r -A=pdf,txt -R=jpg,gif -url=http://example.com

# Use cookies for session persistence
goget --cookies=cookies.txt -url=https://secure.example.com

---

## Development Status
⚠️ Preview Release
This is a `1.0.0-preview` version. Some features (like FTP directory recursion) may still be under development. Contributions are welcome!
