import click
import os
from .database import new_db_connection


def grab_keys():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from keys;")
        except:
            click.echo("\nYou don't have any API keys!  Please enter your keys\n")
            exit()
        rows = cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]

    return access_key, secret_key


@click.group(help="Deploy a Navi front-end using Docker")
def deploy():
    pass


@deploy.command(help="Deploy Navi Tag Center using a Docker container: navigate to http://localhost:5000")
def tag_center():
    if click.confirm('This command downloads the silentninja/navi-ent docker container and runs it on port 5000 using the current navi database. Deploy?'):
        try:
            os.system("docker run -d -p 5000:5000 --mount type=bind,source=\"$(pwd)\",target=/usr/src/app/data silentninja/navi-ent")
        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Was Reporter using a Docker container: navigate to http://localhost:5004")
@click.option("--days", default=60, help="Limit the amount of data being downloaded/reported")
def was_reporter(days):
    a, s = grab_keys()
    command = "docker run -d -p 5004:5004 -e \"access_key={}\" -e \"secret_key={}\" -e {} --mount type=bind,source=$(pwd),target=/usr/src/app/data silentninja/navi:was".format(a,s,days)
    if click.confirm('This command downloads the silentninja/navi:was docker container and runs it on port 5004 using the current navi database. Deploy?'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")
