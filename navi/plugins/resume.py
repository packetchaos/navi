import click
from .api_wrapper import tenb_connection

tio = tenb_connection()


@click.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    tio.scans.resume(scan_id)
