import click
from .database import new_db_connection, create_table
from .api_wrapper import request_data
from .utils import write_to_settings_file


@click.command(help="Enter or Reset your Keys")
@click.argument('access_key', type=str)
@click.argument('secret_key', type=str)
def keys(access_key:str=None, secret_key:str=None) -> tuple:
    if access_key == None or secret_key == None:
        click.echo("Hey you don't have any Keys! Please run this command again with the keys as arguments.")
        exit(2)
    else:
        # Save the configuration to a file called settings.ini
        data = {
            'access_key': access_key,
            'secret_key': secret_key
        }
        write_to_settings_file(data)


# Removing this function because we won't be saving the keys to the DB
# def save_keys(access_key:str, secret_key:str) -> None:
#     database = r"navi.db"
#     conn = new_db_connection(database)
#     create_key_table = """CREATE TABLE IF NOT EXISTS keys (
#                             access_key text,
#                             secret_key text
#                             );"""
#     create_table(conn, create_key_table)
#     with conn:
#         sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
#         cur = conn.cursor()
#         cur.execute(sql, access_key, secret_key)
#     validate_keys()


def validate_keys() -> int:
    result = request_data("GET", "/session")
    return result.status_code
