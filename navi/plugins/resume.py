import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    try:
        request_data('POST', '/scans/' + str(scan_id) + '/resume')
    except Exception as E:
        error_msg(E)
