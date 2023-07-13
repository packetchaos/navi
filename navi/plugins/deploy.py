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
    if click.confirm('This command downloads the packetchaos/tag-center docker container and runs it on port 5000 using the current navi database. Deploy?'):
        try:
            os.system("docker run -d -p 5000:5000 --mount type=bind,source=\"$(pwd)\",target=/usr/src/app/data packetchaos/tag-center")
        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Was Reporter using a Docker container: navigate to http://localhost:5004")
@click.option("--days", default=60, help="Limit the amount of data being downloaded/reported")
def was_reporter(days):
    a, s = grab_keys()
    command = "docker run -d -p 5004:5004 -e \"access_key={}\" -e \"secret_key={}\" -e {} --mount type=bind,source=$(pwd),target=/usr/src/app/data packetchaos/navi_was_reports".format(a,s,days)
    if click.confirm('This command downloads the packetchaos/navi_was_reports docker container and runs it on port 5004 using the current navi database. Deploy?'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Scantime Tagging solution")
def scantags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/scantags".format(a,s)
    if click.confirm('This command downloads the packetchaos/scantags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Discovery then Vuln Scan solution")
@click.option('--trigger', default=None, help="The Scan ID you want to use as the the Trigger Scan, or the first scan in the chain.")
@click.option('--fire', default=None, help="The scan ID you want to use for your Vuln Scan")
@click.option('--targets', default=None, help='The subnet(s) you want to run the discovery scan on.')
def discoverythenvulnscan(trigger, fire, targets):
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} -e trigger={} -e fire={} -e targets={} packetchaos/discovery_then_vulnscan".format(a, s, trigger, fire, targets)
    if click.confirm('This command downloads the packetchaos/discoverythenvulnscan docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Dependency Scan solution")
@click.option('--trigger', default=None, help="The Scan ID you want to use as the the Trigger Scan, or the first scan in the chain.")
@click.option('--fire', default=None, help="The scan ID you want to use for your Vuln Scan")
def dependency_scan(trigger, fire):
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} -e trigger={} -e fire={} packetchaos/dependency_scan".format(a, s, trigger, fire, targets)
    if click.confirm('This command downloads the packetchaos/discoverythenvulnscan docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Critical Tags Docker solution")
def critical_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/critical_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/critical_tags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Tag each asset by the agent group membership")
def agent_group_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/agent_group_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/agent_group_tags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Tag each asset by the ports found open")
def port_tagging():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/port_tagging".format(a,s)
    if click.confirm('This command downloads the packetchaos/port_tagging docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy the All tags solution.  Deploy all tags from all the navi services")
def all_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/all_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/all_tags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy the User Tags solution")
@click.option('--user', required=True, help="The Scan policy ID you want to use as the the Trigger Scan, or the first scan in the chain.")
def usertags(user):
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} -e user={} packetchaos/usertags".format(a, s, user)
    if click.confirm('This command downloads the packetchaos/usertags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")
