import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    try:
        request_data('POST', '/scans/' + str(scan_id) + '/pause')
    except Exception as E:
        error_msg(E)
