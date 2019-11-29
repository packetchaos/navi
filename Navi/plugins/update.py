import click
from .asset_export import asset_export
from .vuln_export import vuln_export


@click.command(help="Update local repository")
def update():
    vuln_export()
    asset_export()
