"""Unit tests for util.py module."""

import pytest
import tempfile
import os
from datetime import datetime, timedelta, UTC
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from util import extract_public_key, verify_artifact_signature


class TestExtractPublicKey:
    """Test cases for extract_public_key function."""

    def test_extract_public_key_valid_cert(self):
        """Test extracting public key from a valid PEM certificate."""
        # Generate a test certificate
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Create a self-signed certificate
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US")])
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Extract public key
        extracted_key = extract_public_key(cert_pem)

        # Verify it's a valid PEM public key
        assert isinstance(extracted_key, bytes)
        assert b"-----BEGIN PUBLIC KEY-----" in extracted_key
        assert b"-----END PUBLIC KEY-----" in extracted_key

        # Verify the extracted key matches the original
        loaded_key = serialization.load_pem_public_key(extracted_key)
        assert isinstance(loaded_key, ec.EllipticCurvePublicKey)

    def test_extract_public_key_invalid_cert(self):
        """Test extracting public key from invalid certificate data."""
        invalid_cert = b"not a valid certificate"

        with pytest.raises(Exception):  # Should raise ValueError or similar
            extract_public_key(invalid_cert)

    def test_extract_public_key_empty_bytes(self):
        """Test extracting public key from empty bytes."""
        with pytest.raises(Exception):
            extract_public_key(b"")


class TestVerifyArtifactSignature:
    """Test cases for verify_artifact_signature function."""

    def test_verify_artifact_signature_valid(self):
        """Test verifying a valid signature."""
        # Generate a key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Serialize public key to PEM
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create test data and sign it
        test_data = b"Hello, World! This is test data."

        signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))

        # Write test data to a temporary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(test_data)
            temp_file = f.name

        try:
            # Verify signature - should not raise an exception
            verify_artifact_signature(signature, public_key_pem, temp_file)
        finally:
            # Clean up
            os.unlink(temp_file)

    # def test_verify_artifact_signature_invalid(self):
    #     """Test verifying an invalid signature."""
    #     # Generate a key pair
    #     private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    #     public_key = private_key.public_key()

    #     # Serialize public key to PEM
    #     public_key_pem = public_key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #     )

    #     # Create test data
    #     test_data = b"Hello, World! This is test data."

    #     # Create an invalid signature (wrong data signed)
    #     wrong_data = b"Different data"
    #     signature = private_key.sign(wrong_data, ec.ECDSA(hashes.SHA256()))

    #     # Write test data to a temporary file
    #     with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
    #         f.write(test_data)
    #         temp_file = f.name

    #     try:
    #         # Verify signature - should raise InvalidSignature
    #         with pytest.raises(InvalidSignature):
    #             verify_artifact_signature(signature, public_key_pem, temp_file)
    #     finally:
    #         # Clean up
    #         os.unlink(temp_file)

    # def test_verify_artifact_signature_wrong_key(self):
    #     """Test verifying signature with wrong public key."""
    #     # Generate two key pairs
    #     private_key1 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    #     private_key2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
    #     public_key2 = private_key2.public_key()

    #     # Serialize public key to PEM (wrong key)
    #     public_key_pem = public_key2.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #     )

    #     # Create test data and sign with key1
    #     test_data = b"Hello, World! This is test data."
    #     signature = private_key1.sign(test_data, ec.ECDSA(hashes.SHA256()))

    #     # Write test data to a temporary file
    #     with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
    #         f.write(test_data)
    #         temp_file = f.name

    #     try:
    #         # Verify signature with wrong key - should raise InvalidSignature
    #         with pytest.raises(InvalidSignature):
    #             verify_artifact_signature(signature, public_key_pem, temp_file)
    #     finally:
    #         # Clean up
    #         os.unlink(temp_file)

    def test_verify_artifact_signature_file_not_found(self):
        """Test verifying signature when file doesn't exist."""
        # Generate a key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Serialize public key to PEM
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signature = b"fake signature"
        fake_file = "/nonexistent/file/path"

        with pytest.raises(FileNotFoundError):
            verify_artifact_signature(signature, public_key_pem, fake_file)

    def test_verify_artifact_signature_invalid_public_key(self):
        """Test verifying signature with invalid public key format."""
        test_data = b"Hello, World!"

        # Write test data to a temporary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(test_data)
            temp_file = f.name

        try:
            invalid_public_key = b"-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"
            signature = b"fake signature"

            with pytest.raises(Exception):  # Should raise ValueError or similar
                verify_artifact_signature(signature, invalid_public_key, temp_file)
        finally:
            os.unlink(temp_file)

