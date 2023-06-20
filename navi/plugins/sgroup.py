import click
from .api_wrapper import tenb_connection

tio = tenb_connection()


@click.command(help="Create a Scanner Group")
@click.option("--name", required=True, help="Name of Scanner Group")
def sgroup(name):
    tio.scanner_groups.create(name)
