import click
from .database import new_db_connection, drop_tables
from .dbconfig import create_passwords_table


@click.command(help="Enter a ssh service account User Name and Password")
@click.option("--username", prompt=True, help="Provide your Access Key")
@click.option("--password", prompt=True, hide_input=True, help="Provide your Secret Key")
def ssh(username, password):
    # create all Tables when keys are added.
    database = r"navi.db"
    drop_conn = new_db_connection(database)
    drop_tables(drop_conn, 'ssh')

    create_passwords_table()

    ssh_dict = (username, password)
    database = r"navi.db"
    conn = new_db_connection(database)

    with conn:
        sql = '''INSERT or IGNORE into ssh(username, password) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, ssh_dict)
