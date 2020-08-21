import click
from .api_wrapper import tenb_connection

tio = tenb_connection()


@click.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    tio.scans.pause(scan_id)
