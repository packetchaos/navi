import click
from .th_asset_export import asset_export
from .th_vuln_export import vuln_export
from sqlite3 import Error


@click.command(help="Update local repository")
@click.option('-assets', is_flag=True, help="Update the Agent data")
@click.option('-vulns', is_flag=True, help="Update the Vulnerability Data data")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def update(assets, vulns, days, exid, threads):
    # Limit the amount of threads to avoid issues
    if threads != 10:
        click.echo("\nUsing {} thread(s) at your request".format(threads))
        if threads not in range(1, 11):
            click.echo("Enter a value between 1 and 10")
            exit()
    try:
        if exid == ' ':
            exid = '0'

        if assets:
            asset_export(days, exid, threads)

        if vulns:
            vuln_export(days, exid, threads)

        if not assets and not vulns:
            vuln_export(days, exid, threads)

            # default for assets should be 90 days to support licensing exports
            asset_export(90, exid, threads)
    except Error as E:
        click.echo("\n Have you entered your keys?\n")
        click.echo("Error: {}".format(E))
