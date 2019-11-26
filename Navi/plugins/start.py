import click
from .api_wrapper import request_data

@click.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    request_data('POST', '/scans/' + str(scan_id) + '/launch')
