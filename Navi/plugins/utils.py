from pathlib import Path
from configparser import ConfigParser


def get_project_root() -> Path:
    return Path(__file__).parent.parent.parent


def get_config_filepath() -> Path:
    config_filepath = Path(get_project_root(), 'settings.ini')
    return config_filepath


def get_keys_from_config() -> dict:
    parser = ConfigParser()
    parser.read(get_config_filepath())
    return {
        'access_key': parser.get('settings', 'access_key'),
        'secret_key': parser.get('settings', 'secret_key')
    }


def write_to_settings_file(data:dict) -> None:
    config_filename = Path(get_config_filepath())
    config = ConfigParser()
    config['settings'] = data
    with open(config_filename, 'w') as configfile:
        config.write(configfile)
