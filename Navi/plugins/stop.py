import click
from .api_wrapper import request_data

@click.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    request_data('POST', '/scans/' + str(scan_id) +'/stop')
