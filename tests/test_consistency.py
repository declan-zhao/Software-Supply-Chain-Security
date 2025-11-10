import subprocess


def test_consistency_no_treeID():
    result = subprocess.run(
        [
            "python",
            "main.py",
            "--consistency",
        ],
        capture_output=True,
        text=True,
    )

    assert result.stdout == "please specify tree id for prev checkpoint\n"


def test_consistency_no_treeSize():
    result = subprocess.run(
        [
            "python",
            "main.py",
            "--consistency",
            "--tree-id",
            "1193050959916656506",
        ],
        capture_output=True,
        text=True,
    )

    assert result.stdout == "please specify tree size for prev checkpoint\n"


def test_consistency_no_rootHash():
    result = subprocess.run(
        [
            "python",
            "main.py",
            "--consistency",
            "--tree-id",
            "1193050959916656506",
            "--tree-size",
            "25996967",
        ],
        capture_output=True,
        text=True,
    )

    assert result.stdout == "please specify root hash for prev checkpoint\n"
