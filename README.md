# goget

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue)](https://go.dev)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%2F%20FreeBSD-lightgrey)](https://github.com/petrbalvin/goget)
[![Version](https://img.shields.io/badge/Version-1.2.0-blue)](https://github.com/petrbalvin/goget)

**A modern command-line download utility for Linux/FreeBSD with IPv6 support**

---

## 📖 Description
```text
goget is a minimalist download tool optimized for UNIX-like systems. It supports HTTP/HTTPS/FTP/FTPS protocols
with parallel transfers, checksum validation, and recursive mirroring. Built with Go's standard library and
golang.org/x packages for maximum compatibility.
```

---

## 🚀 Features

### Core Functionality
```bash
# Download file with IPv6 preference
goget -url https://example.com/file.iso -6

# Resume partial download
goget -url https://example.com/large.zip -c

# Mirror website (3 levels deep)
goget -url https://example.com -r -l=3 -m
```

### Security & Authentication
```bash
# FTPS with TLS encryption
goget -url ftps://user:pass@files.example.com/secret.txt

# HTTP Digest authentication
goget -url http://secure.example.com --digest -http-user=admin
```

---

## 📦 Installation (Linux/FreeBSD)
```bash
# Build from source
git clone https://github.com/petrbalvin/goget.git
cd goget && go build -o goget main.go

# Install system-wide
sudo mv goget /usr/local/bin/
goget --version
```

---

## 🛠️ Usage Examples

### Advanced Features
```bash
# Rate-limited download (2 MB/s)
goget -url https://example.com/4k.mp4 --limit-rate=2M

# FTP wildcard download
goget -url "ftps://user:pass@example.com/logs/*.gz" -6

# Validate SHA1 checksum
goget -url https://example.com/disk.img --checksum=sha1:2fd4e1c67a2d...
```

---

## 🆕 What's New in 1.2.0
```text
- FTP Wildcards: Download multiple files using * and ? patterns
- Rate Limiter: Control bandwidth with --limit-rate
- MIME-Type Filter: Validate Content-Type via -mime-type
- Improved FTPS: Full TLS for control/data channels
```

---

## 🗺️ Roadmap: v1.3.0
```text
■ SOCKS5 Proxy Support       [In Progress]
■ Resumable FTP Transfers    [Planned]
■ SFTP Support               [Planned]
■ SHA-256/SHA-512 Validation [Planned]
■ WebDAV Integration         [Research]
■ ZIP Archive Extraction     [Research]

### Future Proposals:
▢ **Extended Checksum Algorithms**
   - BLAKE3/CRC32 integration
   - Auto-detection based on hash length

▢ **Cloud Storage Enhancements**
   - Google Cloud Storage support
   - Presigned URL generation/validation

▢ **RISC-V Architecture Support**
   - Native builds for RISC-V CPUs
   - CI/CD testing on RISC-V emulators

▢ **Advanced Protocol Features**
   - HTTP/3 via QUIC (experimental)
   - Tor hidden service discovery
```

---

## ⚠️ Limitations
```bash
# Platform support
Currently only compatible with Linux and FreeBSD

# Experimental Features
goget -url https://example.com --http3  # Not fully implemented
```

---

## 🤝 Contributing (UNIX Only)
```bash
# Development setup
git clone https://github.com/petrbalvin/goget.git
cd goget && go test -v ./...
```

```text
1. Fork the repository
2. Test changes on Linux/FreeBSD
3. Submit PR to 'dev' branch

Licensed under BSD-3-Clause. Optimized for UNIX-like systems.
