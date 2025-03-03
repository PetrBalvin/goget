# goget

[![Go Version](https://img.shields.io/badge/Go-1.20+-blue)](https://go.dev)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.1.0-blue)](https://github.com/petrbalvin/goget)

**A modern command-line download utility written in Go with IPv6 support and wget-like features**

---

## 📖 Description
`goget` is a lightweight, cross-platform download tool inspired by `wget`, built with modern Go features. It supports HTTP/HTTPS/FTP/FTPS protocols and offers advanced capabilities like parallel downloads, checksum validation, and recursive mirroring.

---

## 🚀 Features

### Core Functionality
- **Multi-protocol support**: HTTP/HTTPS/FTP/FTPS (explicit mode)
- **IPv6 preference** via `-6` flag
- **Resume interrupted downloads** (`-c`)
- **Recursive downloads** with depth control (`-r -l=5`)
- **Parallel transfers** (`-N=4` for 4 threads)
- **Mirror mode** with directory structure (`-m`)

### Security & Authentication
- **HTTP Basic/Digest auth** (`--digest`, `-http-user`, `-http-pass`)
- **FTP/FTPS authentication** (`-ftp-user`, `-ftp-pass`)
- **TLS for FTPS** (server verification)
- **Checksum validation** (`--checksum=md5:...` or `sha1:...`)

### Advanced Control
- **Extension filtering** (`-A=pdf,zip` / `-R=jpg`)
- **Domain whitelisting** (`-D=example.com`)
- **Retry mechanism** (`-tries=3`)
- **Custom User-Agent** (`-U="MyBot"`)
- **Proxy support** (`-proxy=http://user:pass@host:port`)
- **POST requests** (`--post-data="key=value"`)

### Utilities
- **Cookie persistence** (`--cookies=file.json`)
- **Link conversion** for offline viewing (`-k`)
- **Spider mode** (`--spider` for URL checks)

---

## 📦 Installation

```bash
git clone https://github.com/petrbalvin/goget.git
cd goget
go build -o goget main.go
sudo mv goget /usr/local/bin/

# Verify installation
goget --version
```

---

## 🛠️ Usage Examples

### Basic File Download
```bash
goget -url https://example.com/large.iso -O disk_image.iso
```

### Mirror Website (3 levels deep)
```bash
goget -url https://example.com -r -l=3 -m -k
```

### FTP Download with IPv6
```bash
goget -url ftp://user:pass@example.com/report.pdf -6
```

### Validate Checksum
```bash
goget -url https://example.com/file.tar.gz --checksum=sha1:2fd4e1c67a2d...
```

---

## 🗺️ Roadmap: v1.2.0

### Planned Features
| Feature                  | Status                |
|--------------------------|-----------------------|
| **Full FTPS Support**    | 🛠️ TLS data channels  |
| **POST File Upload**     | ✅ `--post-file`       |
| **Interactive Progress** | 🎨 TUI with metrics   |
| **MIME-Type Filtering**  | 🔍 Filter by type     |
| **HTTP/3 Support**       | 🧪 Experimental QUIC  |

---

## ⚠️ Known Limitations
- ❗ **FTPS Data Encryption**: TLS not applied to FTP data transfers
- ❗ **No SOCKS Proxy**: Only HTTP proxies supported
- ❗ **Basic UI**: Text-based progress (no ETA/speed stats)

---

## 🤝 Contributing
```bash
# Clone repo and create a branch
git clone https://github.com/your-username/goget.git
cd goget
git checkout -b feature/awesome-feature
```

1. Fork the repository
2. Submit PRs to the `dev` branch
3. Follow [code guidelines](CONTRIBUTING.md)
