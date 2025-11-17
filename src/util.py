"""
Utilities for extracting ECDSA public keys from PEM-encoded X.509 certificates
and verifying ECDSA (SHA-256) signatures on artifact files.

Functions
---------
extract_public_key(cert: bytes) -> bytes
    Given a PEM-encoded X.509 certificate (as bytes), extract and return the
    subject public key in PEM (SubjectPublicKeyInfo) format.

verify_artifact_signature(signature: bytes, public_key: bytes,
    artifact_filename: str) -> None
    Load a PEM-encoded public key and verify an ECDSA (SHA-256) signature over
    the contents of the specified file. Prints whether the signature is valid.
    Raises cryptography.exceptions.InvalidSignature if verification fails.

Notes
-----
- Uses the 'cryptography' library (hazmat primitives) for ECDSA verification.
- Assumes the signature was produced with the corresponding private key using
  ECDSA over SHA-256.
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


# extracts and returns public key from a given cert (in pem format)
def extract_public_key(cert):
    """Extract the public key from a PEM-encoded X.509 certificate.

    Args:
        cert (bytes): The PEM-encoded X.509 certificate.

    Returns:
        pem_public_key (bytes): The extracted public key in PEM format.
    """
    # read the certificate
    #    with open("cert.pem", "rb") as cert_file:
    #        cert_data = cert_file.read()

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    # save the public key to a PEM file
    #    with open("cert_public.pem", "wb") as pub_key_file:
    #        pub_key_file.write(public_key.public_bytes(
    #            encoding=serialization.Encoding.PEM,
    #            format=serialization.PublicFormat.SubjectPublicKeyInfo
    #        ))
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(signature, public_key, artifact_filename):
    """Verify the ECDSA signature of an artifact file.

    Args:
        signature (bytes): The signature to verify.
        public_key (bytes): The PEM-encoded public key.
        artifact_filename (str): The path to the artifact file.
    """
    # load the public key
    # with open("cert_public.pem", "rb") as pub_key_file:
    #    public_key = load_pem_public_key(pub_key_file.read())

    # load the signature
    #    with open("hello.sig", "rb") as sig_file:
    #        signature = sig_file.read()

    public_key = load_pem_public_key(public_key)
    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        print("Signature is valid.")
    except InvalidSignature as e:
        print("Signature is invalid:", e)
