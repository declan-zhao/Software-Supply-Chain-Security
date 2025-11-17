import subprocess


def test_debug_mode():
    result = subprocess.run(
        [
            "python",
            "src/main.py",
            "--debug",
        ],
        capture_output=True,
        text=True,
    )

    assert result.stdout == "enabled debug mode\n"
