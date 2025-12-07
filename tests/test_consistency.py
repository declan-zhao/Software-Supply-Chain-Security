import os
import subprocess


def test_consistency_no_treeID():
    result = subprocess.run(
        [
            "python",
            "-m",
            "src.main",
            "--consistency",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )

    assert result.stdout == "please specify tree id for prev checkpoint\n"


def test_consistency_no_treeSize():
    result = subprocess.run(
        [
            "python",
            "-m",
            "src.main",
            "--consistency",
            "--tree-id",
            "1193050959916656506",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )

    assert result.stdout == "please specify tree size for prev checkpoint\n"


def test_consistency_no_rootHash():
    result = subprocess.run(
        [
            "python",
            "-m",
            "src.main",
            "--consistency",
            "--tree-id",
            "1193050959916656506",
            "--tree-size",
            "25996967",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )

    assert result.stdout == "please specify root hash for prev checkpoint\n"
