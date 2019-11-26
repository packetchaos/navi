import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    try:
        request_data('POST', '/scans/' + str(scan_id) + '/launch')
    except Exception as E:
        error_msg(E)
