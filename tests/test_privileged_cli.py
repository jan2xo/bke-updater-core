import pytest

from bke_updater_core.helper import main as helper_main
from bke_updater_core.privileged_cli import _parser


def test_privileged_cli_has_no_install_authority_arguments():
    parser = _parser()
    option_strings = {
        option
        for action in parser._actions
        for option in action.option_strings
    }

    assert "--install-root" not in option_strings
    assert "--entry-point" not in option_strings
    assert "--executable" not in option_strings
    assert "--trust-config" not in option_strings
    assert "--privileged-update" in option_strings
    assert "--runtime-root" in option_strings


def test_legacy_generic_helper_cli_is_rejected():
    with pytest.raises(SystemExit):
        helper_main.main([
            "--install-root", "C:/Program Files/BKE/Product",
            "--staged-root", "C:/Temp/stage",
            "--backup-root", "C:/Temp/backup",
            "--executable", "C:/Program Files/BKE/Product/app.exe",
        ])
