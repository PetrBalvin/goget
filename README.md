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

## Feature Comparison

### Core Functionality
| Feature                | wget                          | goget (1.0.0-preview)        |
|------------------------|-------------------------------|------------------------------|
| **HTTP/HTTPS Support**  | ✅ Full support               | ✅ Full support               |
| **FTP Support**         | ✅ Full support (incl. FTPS)  | ✅ Basic FTP support          |
| **IPv6 Support**        | ✅ Automatic                  | ✅ Explicit (`-6` flag)       |
| **Recursive Downloads** | ✅ Advanced (`-r`, `-l`, `-m`)| ✅ Basic HTML recursion        |
| **Parallel Downloads**  | ✅ (`-N`/`--parallel`)        | ✅ (`-N=THREADS`)             |
| **Resume Downloads**    | ✅ (`-c`)                     | ✅ (`-c`)                     |

### Advanced Features
| Feature                | wget                          | goget (1.0.0-preview)        |
|------------------------|-------------------------------|------------------------------|
| **User-Agent Control**  | ✅ (`-U`)                     | ✅ (`-U`)                     |
| **Proxy Support**       | ✅ (`-e use_proxy=yes`)       | ✅ (`-proxy=URL`)             |
| **Digest Auth**         | ✅ (`--auth-no-challenge`)    | ✅ (`-digest`)                |
| **Cookies Persistence** | ✅ (`--save-cookies`)         | ✅ (`--cookies=FILE` in JSON) |
| **POST Requests**       | ✅ (`--post-data`)            | ❌ Not implemented            |
| **Spider Mode**         | ✅ (`--spider`)               | ❌ Not implemented            |
| **Link Conversion**     | ✅ (`-k`)                     | ❌ Not implemented            |
| **Wildcard Support**    | ✅ (`-A`, `-R`, `-I`)         | ✅ (`-A`, `-R`, `-D`)         |

### Performance & Security
| Feature                | wget                          | goget (1.0.0-preview)        |
|------------------------|-------------------------------|------------------------------|
| **HTTP/2 Support**      | ✅ (via libnghttp2)           | ✅ (native Go HTTP/2)        |
| **Timeout Control**     | ✅ (`--timeout`)              | ✅ (`-timeout=30s`)           |
| **Retry Mechanism**     | ✅ (`-t`/`--tries`)           | ✅ (`-tries=3`)               |
| **Memory Usage**        | Moderate (C-based)           | Optimized (Go garbage collected) |
| **Binary Size**         | ~1.5MB (Linux)               | ~8MB (Go runtime included)   |

### User Experience
| Feature                | wget                          | goget (1.0.0-preview)        |
|------------------------|-------------------------------|------------------------------|
| **Output Control**      | ✅ (`-O`, `-o`, `-a`)         | ✅ (`-O`)                     |
| **Verbosity Levels**    | ✅ (`-v`, `-q`, `--verbose`)  | ✅ (`-v`, `-q`, `-log=LEVEL`) |
| **Progress Display**    | ✅ (built-in)                 | ❌ Not implemented            |
| **Checksum Validation** | ✅ (`--checksum`)             | ❌ Not implemented            |

### Implementation Details
| Feature                | wget                          | goget (1.0.0-preview)        |
|------------------------|-------------------------------|------------------------------|
| **Language**            | C (GNU Wget)                 | Go (modern, cross-platform)  |
| **Dependencies**        | External (libssl, libidn)    | ✅ Zero external dependencies |
| **License**             | GPL-3.0                       | BSD 3-Clause (more permissive) |
| **HTML Parsing**        | Basic regex                  | ✅ Full HTML5 parser (`golang.org/x/net/html`) |

---

## Installation
### Using Go
```bash
# Install directly from source
go install github.com/petrbalvin/goget@latest

# Verify installation
goget --version
```

### Manual Build
```bash
git clone https://github.com/petrbalvin/goget.git
cd goget
go build -o goget main.go
sudo mv goget /usr/local/bin/
```

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
```

---

## Development Status
⚠️ Preview Release
This is a `1.0.0-preview` version. Some features (like FTP directory recursion) may still be under development. Contributions are welcome!
