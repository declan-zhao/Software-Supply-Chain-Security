from main import get_log_entry, get_verification_proof
from jsonschema import validate


logIndex = 128511781

verificationSchema = {
    "type": "object",
    "properties": {
        "checkpoint": {"type": "string"},
        "hashes": {"type": "array", "items": {"type": "string"}},
        "logIndex": {"type": "integer"},
        "rootHash": {"type": "string"},
        "treeSize": {"type": "integer"},
    },
    "required": [
        "checkpoint",
        "hashes",
        "logIndex",
        "rootHash",
        "treeSize",
    ],
}


def test_get_valid_verification():
    log_entry = get_log_entry(logIndex)
    verification_proof = get_verification_proof(log_entry)
    assert verification_proof


def test_verification_schema():
    log_entry = get_log_entry(logIndex)
    verification_proof = get_verification_proof(log_entry)
    validate(instance=verification_proof, schema=verificationSchema)
