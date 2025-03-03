# Contributing to goget

Thank you for your interest in improving **goget**! We welcome contributions from everyone. Below are guidelines to help you get started.

---

## 🐛 Reporting Issues
**Found a bug?** Please follow these steps:
1. **Check existing issues** to avoid duplicates.
2. **Create a new issue** with:
   - **Title**: Clear description (e.g., "FTP download fails over IPv6").
   - **Details**:
     - OS and goget version (`goget --version`).
     - Steps to reproduce.
     - Expected vs. actual behavior.
     - Error logs (use `-v` for verbose output).

**Example issue template**:
```markdown
## Description
[Brief summary of the problem]

## Steps to Reproduce
1. Run `goget -url ...`
2. Observe error: `...`

## Environment
- OS: [e.g., Ubuntu 22.04]
- goget version: [e.g., 1.1.0]
```

---

## 🛠️ Submitting Pull Requests
**Want to fix a bug or add a feature?** Follow these steps:

1. **Fork the repository** and clone it locally.
2. **Create a branch**:
   ```bash
   git checkout -b fix/issue-name  # e.g., fix/ftp-ipv6
   ```
3. **Make your changes**:
   - Follow [coding conventions](#-coding-conventions).
   - Add tests for new features.
4. **Test your changes**:
   ```bash
   go test -v ./...
   ```
5. **Commit changes**: Use descriptive messages (e.g., "fix: handle FTP PASV response parsing").
6. **Push to your fork** and open a PR against the `dev` branch.

**PR Guidelines**:
- Keep PRs small and focused.
- Reference related issues (e.g., "Closes #123").
- Update documentation (README, comments).

---

## 📜 Coding Conventions
- **Formatting**: Use `gofmt` or `goimports`.
- **Comments**: Document public functions and complex logic.
- **Error Handling**: Return meaningful errors with context.
- **Testing**:
  - Cover critical paths (HTTP/FTP clients, recursion logic).
  - Use table-driven tests for edge cases.
- **Dependencies**: Avoid new dependencies unless absolutely necessary.

**Example Code Structure**:
```go
// downloadHTTP handles HTTP/HTTPS downloads
func downloadHTTP(url *url.URL) error {
    // ...
    if err != nil {
        return fmt.Errorf("HTTP request failed: %w", err)
    }
}
```

---

## 📚 Documentation
- Update the **README.md** for new features/flags.
- Add comments to exported functions/types.
- Keep CLI help text (`goget -h`) concise.

---

## 📜 License
By contributing, you agree to license your work under the **BSD-3-Clause** license.

---

## 💬 Questions?
Open a [GitHub Discussion](https://github.com/petrbalvin/goget/discussions) or reach out to the maintainers.

*Thank you for making goget better!* 🚀
