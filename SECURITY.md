# Security Policy

## Supported Versions

This project is currently in active development as part of academic coursework. Security updates will be provided for the following:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

**Note:** As this is an academic project, formal versioning has not been established yet. The `main` branch represents the current supported version. Security patches will be applied to the latest codebase.

### Python Version Support

- **Python 3.8+**: Fully supported
- **Python < 3.8**: Not supported

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please follow these guidelines to ensure responsible disclosure.

### How to Report

**Preferred Method:** Create a private security advisory on GitHub

1. Go to the [Security tab](https://github.com/declan-zhao/Software-Supply-Chain-Security/security) in the repository
2. Click on "Report a vulnerability"
3. Fill out the security advisory form with details about the vulnerability

**Alternative Method:** Email the maintainer directly

- Send an email to: `yz9749@nyu.edu`
- Use the subject line: `[SECURITY] Brief description of the issue`
- Include details about the vulnerability (see "What to Include" below)

**Do NOT:**

- Open a public GitHub issue for security vulnerabilities
- Discuss the vulnerability publicly until it has been addressed
- Exploit the vulnerability beyond what is necessary to demonstrate it

### What to Include

When reporting a security vulnerability, please provide:

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact and severity (e.g., information disclosure, code execution, denial of service)
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Proof of Concept**: If possible, provide a minimal proof of concept (code or commands)
5. **Affected Components**: Which files or functions are affected
6. **Suggested Fix**: If you have ideas for fixing the issue, please share them
7. **Your Contact Information**: So we can reach out if we need clarification

### Vulnerability Scope

We are particularly interested in vulnerabilities related to:

- **Cryptographic Implementation**: Issues in Merkle tree hashing, signature verification, or certificate parsing
- **Input Validation**: Vulnerabilities in parsing log entries, checkpoints, or user-provided artifacts
- **API Security**: Issues with API interactions, including potential for injection or data leakage
- **Dependency Vulnerabilities**: Known security issues in dependencies that could affect this project
- **Authentication/Authorization**: Any issues with key extraction or signature verification
- **Information Disclosure**: Unintended exposure of sensitive data in debug outputs or error messages

**Out of Scope:**

- Issues that require physical access to the system
- Denial of service attacks that don't affect the core functionality
- Issues in dependencies that don't impact this project's security
- Social engineering attacks

### Response Timeline

We aim to:

- **Initial Response**: Acknowledge receipt within 48 hours
- **Initial Assessment**: Provide an initial assessment within 7 days
- **Resolution**: Work towards a fix within 30 days (depending on severity)
- **Disclosure**: Coordinate public disclosure after the fix is available

### Security Update Process

#### Severity Classification

Security vulnerabilities will be classified as:

- **Critical**: Remote code execution, severe information disclosure, or complete compromise of cryptographic verification
- **High**: Significant security impact that could lead to data compromise or verification bypass
- **Medium**: Moderate security impact with limited scope or requiring specific conditions
- **Low**: Minor security issues with minimal impact

#### Update Process

1. **Assessment**: The maintainer will assess the reported vulnerability
2. **Fix Development**: A fix will be developed and tested
3. **Security Patch**: A security patch will be created and applied to the main branch
4. **Documentation**: Security advisories will be published if necessary
5. **Disclosure**: After the fix is available, the vulnerability may be disclosed with appropriate credit

#### Patch Distribution

- Security patches will be committed to the `main` branch
- For critical vulnerabilities, a security advisory will be created on GitHub
- Users are encouraged to pull the latest changes from the repository
- Dependency updates addressing security issues will be documented in commit messages

### Dependency Security

#### Regular Updates

- Dependencies are specified in `requirements.txt` with version constraints
- Security vulnerabilities in dependencies are tracked and updated as needed
- Users should regularly update dependencies using: `pip install --upgrade -r requirements.txt`

#### Security Scanning

This project uses the following tools for security:

- **bandit**: Static security analysis for Python code
- **pip audit**: Dependency vulnerability scanning (recommended for users)

To audit dependencies locally:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

### Security Best Practices for Users

1. **Keep Dependencies Updated**: Regularly update your Python dependencies
2. **Verify Artifacts**: Always verify artifacts using the inclusion proof verification
3. **Checkpoint Verification**: Regularly verify consistency proofs to ensure log integrity
4. **Secure Storage**: Store checkpoints and certificates securely
5. **Network Security**: Use HTTPS when connecting to the Rekor API (default behavior)
6. **Debug Mode**: Be cautious when using debug mode, as it may expose sensitive data in JSON files

### Security Considerations

#### Cryptographic Security

- This project implements RFC 6962 Merkle tree hashing with SHA-256
- ECDSA signature verification uses SHA-256 hashing
- Public keys are extracted from X.509 certificates in PEM format
- All cryptographic operations use the `cryptography` library, which is regularly audited

#### Network Security

- All API communications use HTTPS to the Rekor public instance
- No authentication credentials are stored or transmitted
- Timeout values are set for API requests to prevent hanging connections

#### Input Validation

- Log indices are validated to be non-negative integers
- File paths are validated before processing
- Base64-encoded data is validated during decoding
- Certificate parsing validates PEM format

### Acknowledgments

We appreciate the security research community's efforts to responsibly disclose vulnerabilities. Security researchers who report valid vulnerabilities will be:

- Acknowledged in security advisories (if desired)
- Credited in commit messages or documentation (if desired)
- Appreciated for their contribution to improving the project's security

### Contact

For security-related questions or to report vulnerabilities:

- **GitHub Security Advisory**: [Create a private security advisory](https://github.com/declan-zhao/Software-Supply-Chain-Security/security/advisories/new)
- **Email**: `yz9749@nyu.edu` (use `[SECURITY]` in the subject line)
- **Repository**: [Software-Supply-Chain-Security](https://github.com/declan-zhao/Software-Supply-Chain-Security)

### Additional Resources

- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
