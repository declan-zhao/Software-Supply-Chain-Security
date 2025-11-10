from main import get_log_entry
from jsonschema import validate

import pytest

logIndex = 531825383

# Define the expected schema
logSchema = {
    "type": "object",
    "patternProperties": {
        "^[a-fA-F0-9]{80}$": {
            "type": "object",
            "properties": {
                "body": {"type": "string"},
                "integratedTime": {"type": "integer"},
                "logID": {"type": "string"},
                "logIndex": {"type": "integer"},
                "verification": {
                    "type": "object",
                    "properties": {
                        "inclusionProof": {
                            "type": "object",
                            "properties": {
                                "checkpoint": {"type": "string"},
                                "hashes": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
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
                        },
                        "signedEntryTimestamp": {"type": "string"},
                    },
                    "required": ["inclusionProof", "signedEntryTimestamp"],
                },
            },
            "required": [
                "body",
                "integratedTime",
                "logID",
                "logIndex",
                "verification",
            ],
        }
    },
    "additionalProperties": False,
}


def test_get_valid_log_entry():
    response = get_log_entry(logIndex)
    assert response


def test_get_invalid_log_entry():
    with pytest.raises(
        ValueError, match="log_index must be a non-negative integer."
    ):
        get_log_entry(-1)


def test_log_entry_schema():
    response = get_log_entry(logIndex)
    validate(instance=response, schema=logSchema)
