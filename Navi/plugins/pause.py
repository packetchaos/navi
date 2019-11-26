import click
from .api_wrapper import request_data

@click.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    request_data('POST', '/scans/' + str(scan_id) + '/pause')
