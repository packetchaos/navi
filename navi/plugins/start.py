import click
from .api_wrapper import request_data


@click.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    try:
        request_data('POST', '/scans/' + scan_id + '/launch')
    except:
        # Json error expected. Need to clean up api wrapper to fix this
        pass
