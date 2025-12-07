from src.main import inclusion

import subprocess
import os
import pytest

logIndex = 531825383
artifact = "artifact.md"


def test_valid_inclusion():
    result = subprocess.run(
        [
            "python",
            "-m",
            "src.main",
            "--inclusion",
            str(logIndex),
            "--artifact",
            artifact,
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )

    assert (
        result.stdout
        == "Signature is valid.\nOffline root hash calculation for inclusion verified.\n"
    )


def test_invalid_inclusion_log_index():
    with pytest.raises(
        ValueError, match="log_index must be a non-negative integer."
    ):
        inclusion(str(logIndex), artifact)


def test_invalid_inclusion_artifact():
    with pytest.raises(FileNotFoundError, match="Artifact filepath invalid."):
        inclusion(logIndex, "fakefile")
