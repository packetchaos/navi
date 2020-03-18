import click
from .api_wrapper import request_data


@click.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    try:
        request_data('POST', '/scans/' + scan_id + '/pause')
    except:
        # Json error expected. Need to clean up api wrapper to fix this
        pass
