import click
from .api_wrapper import request_data

@click.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    request_data('POST', '/scans/' + str(scan_id) + '/resume')
