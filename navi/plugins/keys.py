import click
import getpass
from .database import new_db_connection
from .dbconfig import create_keys_table


@click.command(help="Enter or Reset your Keys")
@click.option("-clear", is_flag=True, help="Show my Keys on the screen")
@click.option("--access_key", "--a", default="", help="Provide your Access Key")
@click.option("--secret_key", "--s", default="", help="Provide your Secret Key")
def keys(clear, access_key, secret_key):
    create_keys_table()
    if access_key == "" or secret_key == "":
        click.echo("Hey you don't have any Keys!")
        if clear:
            access_key = input("Please provide your Access Key : ")
            secret_key = input("Please provide your Secret Key : ")
        else:
            access_key = getpass.getpass("Please provide your Access Key : ")
            secret_key = getpass.getpass("Please provide your Secret Key : ")

    key_dict = (access_key, secret_key)
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, key_dict)
