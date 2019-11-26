import click
from .api_wrapper import request_data
from.error_msg import error_msg


@click.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    try:
        request_data('POST', '/scans/' + str(scan_id) + '/stop')
    except Exception as E:
        error_msg(E)
