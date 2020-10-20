import click
from .api_wrapper import request_delete
from .api_wrapper import request_data, tenb_connection

tio = tenb_connection()


@click.group(help="Delete objects from Tenable IO")
def delete():
    pass


@delete.command(help="Delete assets by Tag: tag_category:tag_value - Example - OS:Linux")
@click.argument('tag_string')
def bytag(tag_string):
    tag_tuple = tag_string.split(':')
    cat = tag_tuple[0]
    val = tag_tuple[1]
    if bytag != '':
        click.echo("\nI'm deleting all of the assets associated with your Tag\n")
        payload = {'query': {'field': "tag.{}".format(cat), 'operator': 'set-has', 'value': str(val)}}
        request_data('POST', '/api/v2/assets/bulk-jobs/delete', payload=payload)


@delete.command(help='Delete a Scan by Scan ID')
@click.argument('tid')
def scan(tid):
    click.echo("\nI'm deleting your Scan Now")
    tio.scans.delete(str(tid))


@delete.command(help='Delete an access group by UUID')
@click.argument('tid')
def agroup(tid):
    click.echo("\nI'm deleting your Access Group Now")
    tio.access_groups.delete(str(tid))


@delete.command(help='Delete a target-group by target-group ID')
@click.argument('tid')
def tgroup(tid):
    click.echo("\nI'm deleting your Target group Now")
    tio.target_groups.delete(str(tid))


@delete.command(help='Delete a Policy by Policy ID')
@click.argument('tid')
def policy(tid):
    click.echo("\nI'm deleting your Policy Now")
    tio.policies.delete(str(tid))


@delete.command(help='Delete an Asset by Asset UUID')
@click.argument('tid')
def asset(tid):
    click.echo("\nI'm deleting your asset Now")
    tio.assets.delete(str(tid))


@delete.command(help='Delete a container by \'/repository/image/tag\'')
@click.argument('tid')
def container(tid):
    click.echo("\nI'm deleting your container")
    request_delete('DELETE', '/container-security/api/v2/images/' + str(tid))


@delete.command(help='Delete Tag Value by Value UUID')
@click.argument('tid')
def value(tid):
    click.echo("\nI'm deleting your Tag Value")
    tio.tags.delete(str(tid))


@delete.command(help='Delete Tag Category by Category UUID')
@click.argument('tid')
def category(tid):
    click.echo("\nI'm Deleting your Category")
    tio.tags.delete_category(str(tid))


@delete.command(help='Delete repository from Container Security')
@click.argument('tid')
def repository(tid):
    click.echo("\nI'm Deleting your Repository")
    request_delete('delete', '/container-security/api/v2/' + str(tid))


@delete.command(help='Delete a user by User ID - Not UUID')
@click.argument('tid')
def user(tid):
    click.echo("\nI'm Deleting the User you requested")
    tio.users.delete(str(tid))


@delete.command(help='Delete a user group by the Group ID')
@click.argument('tid')
def usergroup(tid):
    click.echo("\nI'm Deleting the User you requested")
    tio.groups.delete(str(tid))


@delete.command(help='Delete a tag by Category/Value pair')
@click.option('--c', default='', required=True, help="Category to delete")
@click.option('--v', default='', required=True, help="Value to Delete")
def tag(c,v):
    tagdata = request_data('GET', '/tags/values')
    for tags in tagdata['values']:
        if c == tags['category_name']:
            if v == tags['value']:
                value_uuid = tags['uuid']
                request_delete('DELETE', '/tags/values/' + str(value_uuid))
