import os
import subprocess


def test_debug_mode():
    result = subprocess.run(
        [
            "python",
            "-m",
            "src.main",
            "--debug",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "."},
    )

    assert result.stdout == "enabled debug mode\n"
