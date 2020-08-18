import pprint
import click
from .api_wrapper import tenb_connection
from .error_msg import error_msg


@click.command(help="Test the API ex: scans ")
@click.argument('url')
def api(url):
    tio = tenb_connection()
    try:
        data = tio.get(url)
        pprint.pprint(data.json())

    except Exception as E:
        error_msg(E)
