from src.main import get_latest_checkpoint
from jsonschema import validate

import json
import os
import subprocess

checkpoint_schema = {
    "type": "object",
    "properties": {
        "inactiveShards": {"type": "array"},
        "rootHash": {"type": "string"},
        "signedTreeHead": {"type": "string"},
        "treeID": {"type": "string"},
        "treeSize": {"type": "integer"},
    },
    "required": [
        "inactiveShards",
        "rootHash",
        "signedTreeHead",
        "treeID",
        "treeSize",
    ],
}


def test_cli_checkpoint():
    result = subprocess.run(
        [
            "python",
            "-m",
            "src.main",
            "-c",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )
    output = result.stdout
    data = json.loads(output)

    validate(instance=data, schema=checkpoint_schema)


def test_latest_checkpoint():
    data = get_latest_checkpoint()

    validate(instance=data, schema=checkpoint_schema)
