import click
from .asset_export import asset_export
from .vuln_export import vuln_export


@click.command(help="Update local repository")
@click.option('-assets', is_flag=True, help="Update the Agent data")
@click.option('-vulns', is_flag=True, help="Update the Vulnerability Data data")
@click.option('--days', default='30', help="Limit the download to X # of days")
def update(assets, vulns, days):

    if assets:
        asset_export(days)

    if vulns:
        vuln_export(days)

    if not assets and not vulns:
        vuln_export(days)

        # default for assets should be 90 days to support licensing exports
        asset_export(90)
