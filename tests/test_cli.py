# -*- coding: utf-8 -*-
"""Tests for the command line entry."""

from __future__ import print_function

import pytest

from getrom import cli


def test_no_args_prints_usage(capsys):
    """Without arguments the directories and the usage are printed."""
    assert cli.main([]) == 0
    text = capsys.readouterr().out
    assert "getrom" in text


def test_vendor_list(capsys):
    """--list prints all the vendors."""
    assert cli.main(["--list"]) == 0
    text = capsys.readouterr().out
    for name in ("vivo", "xiaomi", "obric", "lenovo", "oplus", "stepaos"):
        assert name in text


def test_obric_list_is_empty(capsys):
    """The device database is gone, --list prints nothing."""
    assert cli.main(["obric", "--list"]) == 0
    assert capsys.readouterr().out == ""


def test_unknown_vendor(capsys):
    """An unknown vendor has to return the exit code 2."""
    assert cli.main(["notexist"]) == 2


def test_missing_device_message(capsys):
    """A missing device has to print a hint instead of raising."""
    assert cli.main(["xiaomi"]) == 0
    text = capsys.readouterr().out
    assert "aurora" in text


@pytest.mark.parametrize("vendor", ["vivo", "xiaomi", "obric", "lenovo", "oplus", "stepaos"])
def test_list_vendor_exit_code(vendor, capsys, monkeypatch, tmp_path):
    """The --list of every vendor exits cleanly and prints no model list."""
    monkeypatch.setenv("GETROM_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("GETROM_DATA_DIR", str(tmp_path / "data"))
    assert cli.main([vendor, "--list"]) == 0
    assert capsys.readouterr().out == ""


def test_model_list_commands_removed(capsys):
    """The device database commands are gone."""
    assert cli.main(["update"]) == 2
    assert cli.main(["models"]) == 2
    assert cli.main(["honor"]) == 2
