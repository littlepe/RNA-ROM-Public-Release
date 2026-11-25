# -*- coding: utf-8 -*-
"""Tests for the paths and the settings."""

from __future__ import print_function

import os

import pytest

from getrom import config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Drop the environment variables that steer the paths.

    Args:
        monkeypatch: The pytest environment patch.
        tmp_path: A temporary directory.
    """
    for name in (
        "GETROM_CONFIG_DIR",
        "GETROM_DATA_DIR",
        "GETROM_HOME",
        "START_DIR",
        "START",
    ):
        monkeypatch.delenv(name, raising=False)


def test_config_dir_env(monkeypatch, tmp_path):
    """GETROM_CONFIG_DIR wins over everything else."""
    monkeypatch.setenv("GETROM_CONFIG_DIR", str(tmp_path / "cfg"))
    assert config.config_dir() == str(tmp_path / "cfg")


def test_data_dir_env(monkeypatch, tmp_path):
    """GETROM_DATA_DIR wins over everything else."""
    monkeypatch.setenv("GETROM_DATA_DIR", str(tmp_path / "data"))
    assert config.data_dir() == str(tmp_path / "data")


def test_home_layout(monkeypatch, tmp_path):
    """GETROM_HOME splits into a config and a data directory."""
    monkeypatch.setenv("GETROM_HOME", str(tmp_path / "home"))
    assert config.config_dir() == os.path.join(str(tmp_path / "home"), "config")
    assert config.data_dir() == os.path.join(str(tmp_path / "home"), "data")


def test_settings_roundtrip(monkeypatch, tmp_path):
    """A setting has to be written into the config directory and read back."""
    monkeypatch.setenv("GETROM_CONFIG_DIR", str(tmp_path / "cfg"))
    assert config.write_setting(".demo", "value")
    assert config.read_setting(".demo") == "value"
    assert config.remove_setting(".demo") is True
    assert config.read_setting(".demo") == ""


def test_platform_name():
    """The platform identifier has to be a known one."""
    assert config.platform_name() in ("windows", "macos", "android", "linux", "other")
