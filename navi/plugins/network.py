import click
from .api_wrapper import request_data


@click.command(help="Change network options")
@click.option("--net", default='00000000-0000-0000-0000-000000000000', help="Select Network ID")
@click.option("--age", default='', help="Adjust Asset Age-out policy for a given network ID")
def network(net, age):
    network_data = request_data('GET', '/networks/' + net)
    name = network_data['name']

    payload = {"assets_ttl_days": age, "description": "TTL adjusted by navi", "name": name}
    if age != '':
        data = request_data('PUT', '/networks/' + net, payload=payload)
        print(data)
