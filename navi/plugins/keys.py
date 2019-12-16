import click
import getpass
from .database import new_db_connection
from .dbconfig import create_keys_table


@click.command(help="Enter or Reset your Keys")
def keys():
    create_keys_table()
    # assumption is that the user keys didn't work or don't exist
    print("Hey you don't have any Keys!")
    access_key = getpass.getpass("Please provide your Access Key : ")
    secret_key = getpass.getpass("Please provide your Secret Key : ")
    key_dict = (access_key, secret_key)

    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, key_dict)
