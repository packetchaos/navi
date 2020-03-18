import click
from .api_wrapper import request_data


@click.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    try:
        request_data('POST', '/scans/' + scan_id + '/stop')
    except:
        # Json error expected. Need to clean up api wrapper to fix this
        pass
