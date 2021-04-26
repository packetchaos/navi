import pprint
import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Test the API ex: scans ")
@click.argument('url')
@click.option('-raw', is_flag=True, help="Return raw Jason")
@click.option('--limit', default=50, help="Change API Request Limit")
@click.option('--offset', default=0, help="Change API Request Offset")
def api(url, raw, limit, offset):
    params = {"limit": limit, "offset": offset}
    try:
        data = request_data('GET', url, params=params)
        if not raw:
            pprint.pprint(data)
        else:
            click.echo(data)

    except Exception as E:
        error_msg(E)
