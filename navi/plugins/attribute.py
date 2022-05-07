import click
from .api_wrapper import request_data


def get_attribute_uuid(name):
    attr_data = request_data('GET', '/api/v3/assets/attributes')
    uuid = 0
    for attr in attr_data['attributes']:
        if name == attr['name']:
            uuid = attr['id']

    return uuid


@click.group(help="Create and Assign Custom Attributes")
def attribute():
    pass


@attribute.command(help="Create an Custom Attribute")
@click.argument('name')
@click.option('--description', default='', help="Add a description for clarity")
def create(name, description):
    payload = {"attributes": [
        {
            "name": name,
            "description": "{} -Updated by Navi".format(description)
        }
    ]}
    data = request_data('POST', '/api/v3/assets/attributes', payload=payload)
    print(data)


@attribute.command(help="Add a custom attribute to an asset")
@click.option('--uuid', default='', help="UUID of the asset")
@click.option('--name', default='', help="Name of the Custom Attribute")
@click.option('--value', default='', help="Value of the Custom Attribute")
def assign(uuid, name, value):
    attr_uuid = get_attribute_uuid(name)
    print(attr_uuid)
    payload = {"attributes": [
        {
            "value": value,
            "id": attr_uuid
        }
    ]}
    assign_attr = request_data("PUT", '/api/v3/assets/{}/attributes'.format(uuid), payload=payload)
    print(assign_attr)
