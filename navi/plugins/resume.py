import click
from .api_wrapper import request_data
from .status import status
from .error_msg import error_msg


@click.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    try:
        request_data('POST', '/scans/' + scan_id + '/resume')
    except:
        # Json error expected. Need to clean up api wrapper to fix this
        pass
