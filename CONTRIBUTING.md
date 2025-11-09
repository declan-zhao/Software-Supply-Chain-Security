# Contributing Guidelines

Thank you for your interest in contributing to the Rekor Transparency Log Verifier! This document outlines the process for contributing to this project, including how to submit pull requests, report issues, and adhere to our code style guidelines.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Reporting Issues](#reporting-issues)
- [Pull Request Process](#pull-request-process)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Type Checking](#type-checking)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Commit Message Guidelines](#commit-message-guidelines)

## Code of Conduct

This project is part of academic coursework. Please be respectful, professional, and constructive in all interactions. We welcome contributions from everyone and are committed to providing a welcoming and inclusive environment.

## Getting Started

1. **Fork the repository** on GitHub

2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/your-username/Software-Supply-Chain-Security.git
   cd Software-Supply-Chain-Security
   ```

3. **Add the upstream repository** as a remote:

   ```bash
   git remote add upstream https://github.com/declan-zhao/Software-Supply-Chain-Security.git
   ```

4. **Create a branch** for your changes:

   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- git

### Setting Up the Development Environment

1. **Create a virtual environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install development dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Verify your installation:**

   ```bash
   python main.py --help
   ```

### Development Dependencies

The project uses the following tools for code quality:

- **Black**: Code formatter (line length: 79 characters)
- **flake8**: Linter for code style checking
- **pylint**: Static code analyzer
- **mypy**: Static type checker
- **bandit**: Security linter

## Reporting Issues

### Before Reporting

1. **Check existing issues** to see if the issue has already been reported
2. **Verify the issue** is reproducible with the latest version
3. **Gather information** about your environment (Python version, OS, etc.)

### How to Report

1. **Create a new issue** on GitHub using the appropriate template (if available)
2. **Use a clear and descriptive title**
3. **Provide detailed information:**
   - Description of the issue
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment information (Python version, OS)
   - Error messages or logs (if applicable)
   - Screenshots (if applicable)

### Issue Types

- **Bug Report**: For reporting bugs or unexpected behavior
- **Feature Request**: For suggesting new features or enhancements
- **Documentation**: For improvements to documentation
- **Question**: For asking questions about the project

**Note:** For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for the proper reporting process.

## Pull Request Process

### Before Submitting

1. **Update your fork:**

   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch:**

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following the code style guidelines

4. **Run all quality checks:**

   ```bash
   # Format code
   black .

   # Run linters
   flake8 .
   pylint *.py

   # Run type checker
   mypy *.py

   # Run security linter
   bandit -r .

   # Run tests (when available)
   pytest
   ```

5. **Commit your changes** with clear commit messages (see [Commit Message Guidelines](#commit-message-guidelines))

6. **Push to your fork:**

   ```bash
   git push origin feature/your-feature-name
   ```

### Submitting a Pull Request

1. **Create a pull request** on GitHub from your fork to the main repository
2. **Use a clear and descriptive title**
3. **Provide a detailed description:**

   - What changes were made
   - Why the changes were made
   - How the changes were tested
   - Any breaking changes
   - Related issues (use "Fixes #issue-number" if applicable)

4. **Ensure all checks pass:**

   - Code formatting (Black)
   - Linting (flake8, pylint)
   - Type checking (mypy)
   - Security scanning (bandit)
   - Tests (if applicable)

5. **Respond to review feedback** promptly and make requested changes

### Pull Request Checklist

- [ ] Code follows the project's style guidelines
- [ ] All linters pass without errors
- [ ] Type checking passes (mypy)
- [ ] Security scanning passes (bandit)
- [ ] Tests are added/updated and pass
- [ ] Documentation is updated (if applicable)
- [ ] Commit messages are clear and descriptive
- [ ] Pull request description is complete

## Code Style Guidelines

### General Principles

- **Readability**: Write code that is easy to read and understand
- **Consistency**: Follow existing code patterns and conventions
- **Simplicity**: Prefer simple, straightforward solutions
- **Documentation**: Document complex logic and public APIs

### Code Formatting

We use **Black** for code formatting with a line length of 79 characters.

**Format your code before committing:**

```bash
black .
```

**Black configuration** (in `pyproject.toml`):

- Line length: 79 characters
- Target Python version: 3.8+

### Python Style Guide

Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines with the following exceptions:

- Line length: 79 characters (enforced by Black)
- Use type hints for function parameters and return values
- Use descriptive variable and function names
- Prefer explicit over implicit

### Linting

#### flake8

Run flake8 to check for style violations:

```bash
flake8 .
```

Common flake8 checks:

- Line length (handled by Black)
- Import organization
- Unused variables
- Syntax errors

#### pylint

Run pylint for comprehensive code analysis:

```bash
pylint *.py
```

Pylint checks for:

- Code quality issues
- Potential bugs
- Code smells
- Style violations

**Target pylint score:** 8.0/10 or higher (for new code)

### Code Organization

- **Imports**: Organize imports in the following order:

  1. Standard library imports
  2. Third-party imports
  3. Local application imports

- **Functions**: Keep functions focused and single-purpose
- **Classes**: Use classes for data structures and complex abstractions
- **Modules**: Keep modules focused on a single responsibility

### Naming Conventions

- **Functions and variables**: Use `snake_case`
- **Classes**: Use `PascalCase`
- **Constants**: Use `UPPER_SNAKE_CASE`
- **Private functions**: Prefix with underscore (`_function_name`)
- **Type variables**: Use descriptive names (e.g., `JSONDict`, `Hasher`)

### Documentation

#### Docstrings

Use Google-style docstrings for all public functions, classes, and modules.

**Function docstring example:**

```python
def verify_inclusion(
    hasher, index, size, leaf_hash, proof, root, debug=False
):
    """Verify an inclusion proof for a given leaf index and root.

    Parameters
    ----------
    hasher : Hasher
        Hashing helper.
    index : int
        Zero-based index of the leaf.
    size : int
        Total number of leaves in the tree.
    leaf_hash : str
        Hex-encoded RFC 6962 leaf hash.
    proof : list[str]
        Sequence of hex-encoded sibling hashes.
    root : str
        Expected hex-encoded Merkle root digest.
    debug : bool, optional
        If True, prints computed vs provided root for inspection.

    Raises
    ------
    RootMismatchError
        If reconstructed root does not match supplied root.
    ValueError
        If tree / proof structural constraints are violated.
    """
```

#### Inline Comments

- Use comments to explain "why" rather than "what"
- Keep comments up-to-date with code changes
- Remove commented-out code before committing

## Testing Requirements

### Test Framework

We recommend using **pytest** for testing (though it's not currently in requirements.txt). When adding tests:

```bash
pip install pytest pytest-cov
```

### Writing Tests

1. **Create test files** with the naming convention: `test_*.py`
2. **Organize tests** in a `tests/` directory (when the test suite grows)
3. **Use descriptive test names** that explain what is being tested
4. **Follow the AAA pattern**: Arrange, Act, Assert

**Test example:**

```python
import pytest
from merkle_proof import DefaultHasher, verify_inclusion

def test_verify_inclusion_valid_proof():
    """Test that a valid inclusion proof is verified correctly."""
    # Arrange
    hasher = DefaultHasher()
    index = 0
    size = 1
    leaf_hash = "abc123..."
    proof = []
    root = "expected_root_hash..."

    # Act & Assert
    verify_inclusion(hasher, index, size, leaf_hash, proof, root)
    # Test passes if no exception is raised
```

### Test Coverage

- Aim for high test coverage (80%+ for new code)
- Focus on testing:

  - Core functionality (Merkle proof verification)
  - Cryptographic operations (hashing, signature verification)
  - Input validation
  - Error handling
  - Edge cases

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_merkle_proof.py

# Run specific test
pytest tests/test_merkle_proof.py::test_verify_inclusion_valid_proof
```

### Test Requirements

- All tests must pass before submitting a pull request
- New features must include tests
- Bug fixes must include regression tests
- Tests should be deterministic (no flaky tests)

## Type Checking

### Type Hints

Use type hints for all function signatures:

```python
def get_log_entry(log_index: int, debug: bool = False) -> JSONDict:
    """Retrieve a log entry from the Rekor API."""
    # ...
```

### mypy Configuration

Run mypy to check type correctness:

```bash
mypy *.py
```

### Type Checking Requirements

- All public functions must have type hints
- Use `typing` module for complex types (e.g., `Dict[str, Any]`)
- Use `Optional` for nullable types
- Use `Union` for multiple possible types

## Security Considerations

### Security Linting

Run bandit to check for security issues:

```bash
bandit -r .
```

### Security Best Practices

- **Input Validation**: Always validate user input
- **Cryptographic Operations**: Use the `cryptography` library for all crypto operations
- **API Calls**: Use HTTPS and validate responses
- **Error Handling**: Don't expose sensitive information in error messages
- **Dependencies**: Keep dependencies up-to-date and review security advisories

### Security Review

All pull requests will be reviewed for security issues. Pay special attention to:

- Input validation and sanitization
- Cryptographic implementations
- API interactions
- Error handling and information disclosure

## Documentation Guidelines

### Code Documentation

- Document all public functions, classes, and modules
- Use Google-style docstrings
- Include parameter descriptions, return values, and exceptions

### README Updates

- Update README.md if adding new features or changing usage
- Update installation instructions if dependencies change
- Update examples if CLI interface changes

### Inline Documentation

- Add comments for complex logic
- Explain "why" not "what"
- Keep comments up-to-date

## Commit Message Guidelines

### Commit Message Format

Use clear, descriptive commit messages:

```text
Short summary (50 characters or less)

More detailed explanation if necessary. Wrap at 72 characters.
Explain what and why vs. how.

- Bullet points are okay, too
- Use a hyphen or asterisk for the bullet
```

### Commit Message Examples

**Good:**

```text
Fix Merkle proof verification for edge case

Handle the case where tree size is 1 in verify_inclusion.
This fixes a bug where single-node trees would fail verification.

Fixes #123
```

**Bad:**

```text
fix bug
```

### Commit Types

Use prefixes to indicate the type of change:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

### Commit Guidelines

- **One logical change per commit**
- **Write clear, descriptive messages**
- **Reference issues** using "Fixes #issue-number"
- **Keep commits focused** and atomic

## Review Process

### What to Expect

1. **Automated Checks**: Your PR will run automated checks (linting, type checking, tests)
2. **Code Review**: A maintainer will review your code
3. **Feedback**: You may receive feedback requesting changes
4. **Approval**: Once approved, your PR will be merged

### Responding to Feedback

- **Be open to feedback**: Code review is a learning opportunity
- **Ask questions**: If feedback is unclear, ask for clarification
- **Make requested changes**: Address all review comments
- **Update your PR**: Push new commits to address feedback

## Getting Help

If you need help or have questions:

1. **Check the documentation**: README.md, code comments, docstrings
2. **Search existing issues**: Your question may have been asked before
3. **Open an issue**: Use the "Question" label
4. **Contact the maintainer**: <yz9749@nyu.edu>

## Additional Resources

- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [Black Documentation](https://black.readthedocs.io/)
- [pytest Documentation](https://docs.pytest.org/)
- [mypy Documentation](https://mypy.readthedocs.io/)
- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)

## Thank You

Thank you for taking the time to contribute to this project! Your contributions help make this project better for everyone.
