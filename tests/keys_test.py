import click
import pytest
from pathlib import Path
from click.testing import CliRunner
from configparser import ConfigParser
from navi.plugins.keys import keys, validate_keys
from navi.plugins.utils import get_config_filepath


def test_keys_with_fake_keys():
    runner = CliRunner()
    result = runner.invoke(keys, ['access_key', 'secret_key'])
    assert result.exit_code == 0


def test_keys_with_three_inputs():
    runner = CliRunner()
    result = runner.invoke(keys, ['access_key', 'secret_key', 'butt'])
    assert result.exit_code == 2


def test_keys_with_no_inputs_or_keys():
    runner = CliRunner()
    result = runner.invoke(keys, [])
    assert 'Usage: keys [OPTIONS] ACCESS_KEY SECRET_KEY\nTry "keys --help" for help.\n\nError: Missing argument "ACCESS_KEY".\n' in result.output
    assert result.exit_code == 2


def test_keys_settings_file_created():
    runner = CliRunner()
    result = runner.invoke(keys, ['access is my key', 'no it is a secret'])
    config_filepath = get_config_filepath()
    assert config_filepath.exists() == True


def test_keys_in_settings_file():
    runner = CliRunner()
    access_key = 'I am the access key'
    secret_key = 'I am the secret key'
    result = runner.invoke(keys, [access_key, secret_key])
    config_filepath = get_config_filepath()
    parser = ConfigParser()
    parser.read(config_filepath)
    assert parser.get('settings', 'access_key') == access_key
    assert parser.get('settings', 'secret_key') == secret_key
