import click
from .th_asset_export import asset_export
from .th_vuln_export import vuln_export
from .th_compliance_export import compliance_export
from .fixed_export import fixed_export
from .database import new_db_connection, drop_tables, create_table
from .dbconfig import create_tagrules_table
from .was_export import grab_scans
from .epss import update_navi_with_epss
from .tagrule_export import export_tags


def threads_check(threads):
    if threads != 20:  # Limit the amount of threads to avoid issues
        click.echo("\nUsing {} thread(s) at your request".format(threads))
        if threads not in range(1, 21):
            click.echo("Enter a value between 1 and 20")
            exit()


@click.group(help="Update the local Navi DB, Change Base URL, and update EPSS")
def update():
    pass


@update.command(help="Perform a full update (30d Vulns / 90d Assets); Delete the current Database")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--days', default=None, help="Limit the download to X # of days")
@click.option('--c', default=None, help="Isolate your update to a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update to a tag using the provided value")
@click.option('--state', multiple=True, default=["open", "reopened"], type=click.Choice(['open', 'reopened', 'fixed']),
              help='Isolate your update to a particular finding state')
@click.option('--severity', multiple=True, default=["critical", "high", "medium", "low", "info"],
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help='Isolate your update to a particular finding severity')
def full(threads, days, c, v, state, severity):
    if threads:
        threads_check(threads)

    exid = '0'

    if days is None:
        vuln_export(30, exid, threads, c, v, list(state), list(severity))
        asset_export(90, exid, threads, c, v)
    else:
        vuln_export(days, exid, threads, c, v, list(state), list(severity))
        asset_export(days, exid, threads, c, v)


@update.command(help="Update the Asset Table")
@click.option('--days', default='90', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--c', default=None, help="Isolate your update by a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update by a tag using the provided value")
def assets(threads, days, exid, c, v):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    asset_export(days, exid, threads, c, v)


@update.command(help="Update the vulns Table")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-20)")
@click.option('--c', default=None, help="Isolate your update by a tag using the provided category")
@click.option('--v', default=None, help="Isolate your update by a tag using the provided value")
@click.option('--state', multiple=True, default=["open", "reopened"], type=click.Choice(['open', 'reopened', 'fixed']),
              help='Isolate your update to a partiular finding state')
@click.option('--severity', multiple=True, default=["critical", "high", "medium", "low", "info"],
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help='Isolate your update to a particular finding state')
def vulns(threads, days, exid, c, v, state, severity):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    vuln_export(days, exid, threads, c, v, list(state), list(severity))


@update.command(help="Update the Compliance data")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-20)")
def compliance(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    compliance_export(days, exid, threads)


@update.command(help="Update Navi DB with Fixed data for SLA processing")
@click.option('--c', default='', help="Tag Category name")
@click.option('--v', default='', help="Tag Value")
@click.option('--days', default='30', help="Limit the download to X # of days")
def fixed(c, v, days):
    fixed_export(c, v, days)


@update.command(help="Change the Base URL for Navi")
@click.argument('new_url')
def url(new_url):
    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'url')
    create_url_table = """CREATE TABLE IF NOT EXISTS url (name text, url text);"""
    create_table(conn, create_url_table)

    info = ("Custom URL", new_url)
    with conn:
        sql = '''INSERT or IGNORE into url (name, url) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, info)


@update.command(help="Update the Navi DB with WAS data")
@click.option('--days', default='30', help="Limit the data downloaded a number of days")
def was(days):
    grab_scans(days)


@update.command(help="Populate Navi DB with EPSS data")
@click.option('--day', '--d', required=True, help="Day of the Month; EX: 01 NOT 1")
@click.option('--month', '--m', required=True, help="Month of the year;EX: 04 NOT 4")
@click.option('--year', '--y', required=True, help="Year of your desire;EX: 2023 NOT 23")
def epss(day, month, year):
    update_navi_with_epss(day, month, year)


@update.command(help="Popluate the DB with Tag rules for migrations")
def tagrules():
    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'tagrules')
    create_tagrules_table()
    export_tags()

