import click
from .th_asset_export import asset_export
from .th_vuln_export import vuln_export
from .was_data_export import grab_scans
from .th_compliance_export import compliance_export
from .fixed_export import fixed_export
from .database import new_db_connection, drop_tables, create_table


def threads_check(threads):
    if threads != 10:  # Limit the amount of threads to avoid issues
        click.echo("\nUsing {} thread(s) at your request".format(threads))
        if threads not in range(1, 11):
            click.echo("Enter a value between 1 and 10")
            exit()


@click.group(help="Update the local Navi repository - saved in your current dir")
def update():
    pass


@update.command(help="Perform a full update (30d Vulns / 90d Assets); Delete the current Database")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def full(threads):

    if threads:
        threads_check(threads)

    exid = '0'

    vuln_export(30, exid, threads)
    asset_export(90, exid, threads)


@update.command(help="Update the Asset Table")
@click.option('--days', default='90', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def assets(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    asset_export(days, exid, threads)


@update.command(help="Update the vulns Table")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def vulns(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    vuln_export(days, exid, threads)


@update.command(help="Update the Was Data")
def was():
    grab_scans()


@update.command(help="Update the Compliance data")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
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
