import click
from .api_wrapper import request_delete
from .api_wrapper import request_data


@click.command(help="Delete an Object by it's ID")
@click.argument('tid')
@click.option('-scan', is_flag=True, help='Delete a Scan by Scan ID')
@click.option('-agroup', is_flag=True, help='Delete an access group by access group ID')
@click.option('-tgroup', is_flag=True, help='Delete a target-group by target-group ID')
@click.option('-policy', is_flag=True, help='Delete a Policy by Policy ID')
@click.option('-asset', is_flag=True, help='Delete an Asset by Asset UUID')
@click.option('-container', is_flag=True, help='Delete a container by \'/repository/image/tag\'')
@click.option('-repository', is_flag=True, help='Delete Repository from Container Security')
@click.option('-value', is_flag=True, help="Delete a Tag by Value UUID")
@click.option('-category', is_flag=True, help="Delete a Tag Category by UUID")
@click.option('--c', default='', help="Delete a tag by Category / Value pair. Requires --v")
@click.option('--v', default='', help="Delete a tag by Category / Value pair. Requires --c")
@click.option('--bytag', default='', help="Delete assets by Tag. Ex: OS:Linux -- navi delete Linux --bytag tag.OS")
@click.option('-user', is_flag=True, help="Delete a user by User ID - API BUG! - Doesn't work right now")
@click.option('-usergroup', is_flag=True, help="Delete a user group by the Group ID")
def delete(tid, scan, agroup, tgroup, policy, asset, container, repository, value, category, bytag, c, v, user, usergroup):

    if bytag != '':
        print("\nI'm deleting all of the assets associated with your Tag\n")
        payload = {'query': {'field': str(bytag), 'operator': 'set-has', 'value': str(tid)}}
        request_data('POST', '/api/v2/assets/bulk-jobs/delete', payload=payload)

    if c != '':
        if v == '':
            print("value is required.  Please use --v option when deleting tab by value pair")
            exit()
        else:
            tagdata = request_data('GET', '/tags/values')
            for tags in tagdata['values']:
                if c == tags['category_name']:
                    if v == tags['value']:
                        value_uuid = tags['uuid']
                        request_delete('DELETE', '/tags/values/' + str(value_uuid))

    if scan:
        print("\nI'm deleting your Scan Now")
        request_delete('DELETE', '/scans/' + str(tid))

    if agroup:
        print("\nI'm deleting your Access Group Now")
        request_delete('DELETE', ('/access-groups/' + str(tid)))

    if tgroup:
        print("\nI'm deleting your Target group Now")
        request_delete('DELETE', ('/target-groups/' + str(tid)))

    if policy:
        print("\nI'm deleting your Policy Now")
        request_delete('DELETE', ('/policies/' + str(tid)))

    if asset:
        print("\nI'm deleting your asset Now")
        request_delete('DELETE', '/workbenches/assets/' + str(tid))

    if container:
        print("\nI'm deleting your container")
        request_delete('DELETE', '/container-security/api/v2/images/' + str(tid))

    if value:
        print("\nI'm deleting your Tag Value")
        request_delete('DELETE', '/tags/values/' + str(tid))

    if category:
        print("\nI'm Deleting your Category")
        request_delete('delete', '/tags/categories/' + str(tid))

    if repository:
        print("\nI'm Deleting your Repository")
        request_delete('delete', '/container-security/api/v2/' + str(repository))

    if user:
        print("\nI'm Deleting the User you requested")
        request_delete('delete', '/users/' + str(user))

    if usergroup:
        print("\nI'm Deleting the User you requested")
        request_delete('delete', '/groups/' + str(usergroup))
