# Software Supply Chain Security - Rekor Transparency Log Verifier

A Python CLI tool for verifying entries in the Rekor transparency log, implementing Merkle proof verification and artifact signature validation according to RFC 6962 (Certificate Transparency) standards.

## Project Description

This project provides a command-line interface for interacting with the [Rekor transparency log](https://rekor.sigstore.dev), a public, append-only, tamper-evident log designed for software supply chain security. The tool enables users to:

- **Fetch log entries** by index from the Rekor API
- **Verify artifact signatures** using ECDSA public keys extracted from X.509 certificates
- **Verify Merkle inclusion proofs** to confirm that artifacts are included in the log
- **Fetch latest checkpoints** from the Rekor server
- **Verify Merkle consistency proofs** to ensure the log maintains append-only properties between checkpoints

The implementation follows RFC 6962 specifications for Merkle tree hashing, using SHA-256 with domain-separated prefixes (0x00 for leaves, 0x01 for internal nodes).

## Features

- ✅ RFC 6962-compliant Merkle tree hashing and proof verification
- ✅ ECDSA signature verification using X.509 certificates
- ✅ Merkle inclusion proof verification
- ✅ Merkle consistency proof verification between checkpoints
- ✅ Debug mode for inspecting API responses
- ✅ Type checking and security linting support

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. **Clone the repository:**

   ```bash
   git clone https://github.com/declan-zhao/Software-Supply-Chain-Security.git
   cd Software-Supply-Chain-Security
   ```

2. **Create a virtual environment (recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

## Dependencies

### Runtime Dependencies

- **requests** (>=2.32.5, <3): HTTP library for interacting with the Rekor API
- **cryptography** (>=46.0.1, <47): Cryptographic primitives for ECDSA signature verification and X.509 certificate parsing

### Development Dependencies

- **flake8** (>=7.3.0, <8): Python linter for code style checking
- **pylint** (>=3.3.8, <4): Python static code analyzer
- **mypy** (>=1.18.2, <2): Static type checker for Python
- **bandit** (>=1.8.6, <2): Security linter for Python code

### Code Formatting

The project uses **Black** for code formatting with a line length of 79 characters (configured in `pyproject.toml`).

## Usage

### Command-Line Interface

The tool provides several commands for interacting with the Rekor transparency log:

#### Get Latest Checkpoint

Fetch and display the latest checkpoint from the Rekor server:

```bash
python main.py --checkpoint
```

With debug mode (saves checkpoint to `checkpoint.json`):

```bash
python main.py --checkpoint --debug
```

#### Verify Inclusion Proof

Verify that an artifact is included in the log and verify its signature:

```bash
python main.py --inclusion <log_index> --artifact <artifact_filepath>
```

Example:

```bash
python main.py --inclusion 126574567 --artifact artifact.bundle
```

This command will:

1. Fetch the log entry from the Rekor API
2. Extract and verify the artifact's ECDSA signature
3. Verify the Merkle inclusion proof
4. Print verification results

#### Verify Consistency Proof

Verify that the log maintains append-only properties between two checkpoints:

```bash
python main.py --consistency --tree-id <tree_id> --tree-size <tree_size> --root-hash <root_hash>
```

Example:

```bash
python main.py --consistency --tree-id "abc123" --tree-size 1000 --root-hash "a1b2c3..."
```

This command will:

1. Fetch the latest checkpoint from the server
2. Retrieve the consistency proof between the previous and latest checkpoint
3. Verify that the log is consistent (append-only)
4. Print verification results

#### Debug Mode

Enable debug mode to save API responses to JSON files for inspection:

```bash
python main.py --checkpoint --debug
```

Debug mode saves:

- `checkpoint.json`: Latest checkpoint data
- `log_entry.json`: Log entry data (when using `--inclusion`)
- `consistency_proof.json`: Consistency proof data (when using `--consistency`)

### Complete Example Workflow

1. **Get the latest checkpoint:**

   ```bash
   python main.py --checkpoint
   ```

2. **Verify an artifact's inclusion in the log:**

   ```bash
   python main.py --inclusion 126574567 --artifact artifact.bundle
   ```

3. **Verify consistency with a previous checkpoint:**

   ```bash
   python main.py --consistency --tree-id "abc123" --tree-size 1000 --root-hash "a1b2c3..."
   ```

## Project Structure

```text
.
├── main.py              # Main CLI entry point and Rekor API client
├── merkle_proof.py      # RFC 6962 Merkle tree hashing and proof verification
├── util.py              # Public key extraction and signature verification utilities
├── requirements.txt     # Python dependencies
├── pyproject.toml       # Black code formatter configuration
└── README.md           # This file
```

## API Endpoint

The tool connects to the public Rekor instance at:

- **Base URL**: `https://rekor.sigstore.dev/api/v1`

## Security Notes

- All signature verification uses ECDSA with SHA-256
- Merkle proofs follow RFC 6962 specifications for tamper-evident logging
- Public keys are extracted from X.509 certificates in PEM format
- The tool performs offline verification of Merkle proofs without trusting the server

## License

This project is part of coursework for CS-GY 9223 Software Supply Chain Security at NYU.

## Contributing

This is an academic project. For questions or issues, please contact the repository maintainer.

## References

- [Rekor Project](https://github.com/sigstore/rekor)
- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [Sigstore Documentation](https://docs.sigstore.dev/)
