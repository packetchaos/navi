import pprint
import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Explore the API using simple GET requests ex: 'navi api /scans ")
@click.argument('url')
@click.option('-raw', is_flag=True, help="Return raw Json")
@click.option('--limit', default=50, help="Change API Request Limit")
@click.option('--offset', default=0, help="Change API Request Offset")
@click.option('-post', is_flag=True, help="Use POST instead of GET")
def api(url, raw, limit, offset, post):
    params = {"limit": limit, "offset": offset}
    try:
        if post:
            data = request_data('POST', url, params=params)
        else:
            data = request_data('GET', url, params=params)

        if not raw:
            pprint.pprint(data)
        else:
            click.echo(data)

    except Exception as E:
        error_msg(E)
