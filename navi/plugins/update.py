import click
from .th_asset_export import asset_export
from .th_vuln_export import vuln_export
# from .vuln_export import vuln_export
from sqlite3 import Error


@click.command(help="Update local repository")
@click.option('-assets', is_flag=True, help="Update the Agent data")
@click.option('-vulns', is_flag=True, help="Update the Vulnerability Data data")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default=' ', help="Download using a specified Export ID")
def update(assets, vulns, days, exid):
    try:
        if exid == ' ':
            exid = '0'

        if assets:
            asset_export(days, exid)

        if vulns:
            vuln_export(days, exid)

        if not assets and not vulns:
            vuln_export(days, exid)

            # default for assets should be 90 days to support licensing exports
            asset_export(90, exid)
    except Error as E:
        print("\n Have you entered your keys?\n")
        print("Error: ", E, "\n")
