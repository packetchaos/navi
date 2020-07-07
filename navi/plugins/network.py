import click
from .api_wrapper import request_data


@click.command(help="Change network options")
@click.option("--net", default='00000000-0000-0000-0000-000000000000', help="Select Network ID")
@click.option("--age", default='', help="Adjust Asset Age-out policy for a given network ID")
def network(net, age):
    payload = {"assets_ttl_days": age}
    if age != '':
        data = request_data('PUT', '/networks/' + net, payload=payload)
        print(data)
