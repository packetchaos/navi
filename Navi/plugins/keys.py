import click
import getpass
from .database import new_db_connection, create_table

@click.command(help="Enter or Reset your Keys")
def keys():
    #assumption is that the user keys didn't work or don't exist
    print("Hey you don't have any Keys!")
    access_key = getpass.getpass("Please provide your Access Key : ")
    secret_key = getpass.getpass("Please provide your Secret Key : ")

    database = r"navi.db"
    conn = new_db_connection(database)
    create_key_table = """CREATE TABLE IF NOT EXISTS keys (
                            access_key text,
                            secret_key text
                            );"""
    create_table(conn, create_key_table)
    dict = (access_key, secret_key)
    with conn:
        sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, dict)
