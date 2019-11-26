import click
from .api_wrapper import request_data


@click.command(help="Delete an Object by it's ID")
@click.argument('id')
@click.option('-scan', is_flag=True, help='Delete a Scan by Scan ID')
@click.option('-agroup', is_flag=True, help='Delete an access group by access group ID')
@click.option('-tgroup', is_flag=True, help='Delete a target-group by target-group ID')
@click.option('-policy', is_flag=True, help='Delete a Policy by Policy ID')
@click.option('-asset', is_flag=True, help='Delete an Asset by Asset UUID')
@click.option('-container', is_flag=True, help='Delete a container by \'/repository/image/tag\'')
@click.option('-tag', is_flag=True, help="Delete a Tag by Value UUID")
@click.option('-category', is_flag=True, help="Delete a Tag Category by UUID")
def delete(tid, scan, agroup, tgroup, policy, asset, container, tag, category):

    if scan:
        print("I'm deleting your Scan Now")
        request_data('DELETE', '/scans/'+str(tid))

    if agroup:
        print("I'm deleting your Access Group Now")
        request_data('DELETE', ('/access-groups/'+str(tid)))

    if tgroup:
        print("I'm deleting your Target group Now")
        request_data('DELETE', ('/target-groups/'+str(tid)))

    if policy:
        print("I'm deleting your Policy Now")
        request_data('DELETE', ('/policies/' + str(tid)))

    if asset:
        print("I'm deleting your asset Now")
        request_data('DELETE', '/workbenches/assets/' + str(tid))

    if container:
        print("I'm deleting your container")
        request_data('DELETE', '/container-security/api/v2/images' + str(tid))

    if tag:
        print("I'm deleting your Tag Value")
        request_data('DELETE', '/tags/values/' + str(tid))

    if category:
        print("I'm Deleting your Category")
        request_data('DELETE', '/tags/categories/'+str(tid))
