import click
from .api_wrapper import tenb_connection

tio = tenb_connection()


@click.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    tio.scans.stop(scan_id)
