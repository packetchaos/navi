import click
import getpass
from .database import new_db_connection, create_table, drop_tables


@click.command(help="Enter or Overwrite your SMTP information")
def smtp():
    # update using ex: https://gist.github.com/BietteMaxime/f75ae41f7b4557274a9f
    click.echo("Hey you don't have any SMTP information!")
    server = input("Enter the Email servers address - ex: smtp.gmail.com : ")
    port = input("Enter the port your Email server uses - ex: 587: ")
    from_email = input("Enter your Email Address - ex: youremail@gmail.com ")
    password = getpass.getpass("Enter your email password - : ")

    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'smtp')
    create_smtp_table = """CREATE TABLE IF NOT EXISTS smtp (
                            server text,
                            port text,
                            from_email text, 
                            password text 
                            );"""
    create_table(conn, create_smtp_table)

    info = (server, port, from_email, password)
    with conn:
        sql = '''INSERT or IGNORE into smtp(server, port, from_email, password) VALUES(?,?,?,?)'''
        cur = conn.cursor()
        cur.execute(sql, info)
