import pprint
import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Test the API ex: scans ")
@click.argument('url')
def api(url):

    try:
        data = request_data('GET', url)
        pprint.pprint(data)

    except Exception as E:
        error_msg(E)
