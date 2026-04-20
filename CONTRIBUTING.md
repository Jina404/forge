# Contributing to Forge

Thank you for your interest in contributing to Forge! This document provides guidelines to make the process smooth and effective.

## Code of Conduct

Please read and follow our CODE_OF_CONDUCT.md.

## How to Contribute

### Reporting Bugs

- Check if the bug is already reported in [Issues](https://github.com/Jina404/forge/issues).
- If not, open a new issue with:
  - Clear title and description.
  - Steps to reproduce.
  - Expected vs actual behavior.
  - Your OS and Go version.
  - Any relevant logs or screenshots.

### Suggesting Features

- Open an issue with the label `enhancement`.
- Explain the feature and why it would be useful.

### Submitting Code Changes

1. **Fork the repository** and clone your fork locally.
2. **Create a new branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
3. Make your changes following our coding style:
    Run go fmt ./... to format code.

    Run go vet ./... to check for issues.

    Add tests if applicable.
4. Commit your changes with a clear message:
    ```bash
    git commit -m "Add feature: description"
5. Push to your fork:
    ```bash
    git push origin feature/your-feature-name
    
6. Open a Pull Request against the main branch of Jina404/forge.

### Pull Request Guidelines

    -Keep PRs focused on a single change.

    -Link to any related issues.

    -Update documentation if your change affects usage.

    -Ensure all tests pass.

### Development Setup
```bash
git clone https://github.com/Jina404/forge.git
cd forge
go mod download
go build -o forge ./cmd/forge
```


### Project Structure
forge/
├── cmd/forge/          # CLI entry point
├── pkg/
│   ├── engine/         # Load generation and worker pools
│   ├── metrics/        # Statistics collection
│   ├── fuzzer/         # Payload management
│   └── detector/       # Vulnerability detection
└── go.mod



### Questions?
Feel free to open an issue or contact the maintainer.

Thank you for contributing!
EOF


---

### 2. CODE_OF_CONDUCT.md

Standard for open-source projects (based on Contributor Covenant).

```bash
cat > CODE_OF_CONDUCT.md << 'EOF'
# Code of Conduct

## Our Pledge

We pledge to make participation in our project and community a harassment-free experience for everyone.

## Our Standards

Examples of behavior that contributes to a positive environment:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community

Examples of unacceptable behavior:
- Harassment, insults, or derogatory comments
- Publishing others' private information without permission
- Any conduct which could reasonably be considered inappropriate

## Enforcement

Instances of abusive behavior may be reported to the maintainer via GitHub issues. All complaints will be reviewed and investigated.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org/).

