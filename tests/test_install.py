"""install.sh: the installer and the kernel share one directory by default
($NSBOS_PREFIX, ~/.ngari/kernel), so its uninstall advice must not delete the
kernel's data and key along with the code."""

import re
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parent.parent / "install.sh").read_text()


def test_the_default_prefix_is_the_kernels_default_data_dir():
    assert 'PREFIX="${NSBOS_PREFIX:-$HOME/.ngari/kernel}"' in SCRIPT
    assert "NGARI_DATA_DIR=$PREFIX" in SCRIPT


def test_uninstall_removes_only_what_the_installer_wrote():
    line = next(ln for ln in SCRIPT.splitlines() if "Uninstall:" in ln)
    targets = re.findall(r"\$PREFIX\S*", line)
    assert targets == ["$PREFIX/src", "$PREFIX/venv"], line


def test_the_closing_message_names_the_key_to_back_up():
    assert "$PREFIX/sovereign/keys/master.key" in SCRIPT
    assert "Back it up" in SCRIPT
