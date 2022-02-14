import click
from .database import db_query
from .api_wrapper import request_data, tenb_connection

tio = tenb_connection()


def check_agroup_exists(aname):
    rvalue = 'no'
    for group in tio.access_groups.list():
        if str(group['name']).lower() == str(aname).lower():
            rvalue = group['id']
    return rvalue


@click.command(help="Create an Access group Based on a Tag - DEPRECATED in T.io")
@click.option('--name', default='', required=True, help="Choose a Name for your Access Group.")
@click.option('--c', default='', required=True, help="Tag Category name to use")
@click.option('--v', default='', required=True, help="Tag Value to use")
@click.option('--user', default='', help="The user you want to Assign to the Access Group - username@domain")
@click.option('--usergroup', default='', help="The User Group you want to assign to the Access Group")
@click.option('--perm', type=click.Choice(['scan', 'view', 'scanview'], case_sensitive=False), required=True)
def agroup(name, c, v, user, usergroup, perm):
    permission = []
    choice = 'none'
    permtype = 'none'

    if user == '' and usergroup == '':
        click.echo("\nYou Need to use '--user' or '--usergroup' command and supply "
                   "a user or group. e.g: user@yourdomain or Linux Admins\n")
        exit()

    if user != '':
        permtype = 'user'
        choice = user

    if usergroup != '':
        permtype = 'group'
        choice = usergroup

    if perm.lower() == 'scanview':
        permission = ["CAN_VIEW", "CAN_SCAN"]

    elif perm.lower() == 'view':
        permission = ["CAN_VIEW"]

    elif perm.lower() == 'scan':
        permission = ["CAN_SCAN"]

    assets = db_query("SELECT tag_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")

    # Grab the first UUID...UUIDs returned are duplicates due to the db structure
    tag_uuid = [assets[0][0]]

    if tag_uuid:
        payload = {"name": str(name), "access_group_type": "MANAGE_ASSETS", "rules": [{"type": "tag_uuid", "operator": "set-has", "terms": tag_uuid}],
                   "principals": [{"permissions": permission, "type": permtype, "principal_name": choice}]}

        # Check to see if the group exists
        answer = check_agroup_exists(str(name))

        try:
            # Check to see if the list has any IPs in it.
            if answer == 'no':
                new_access_group = request_data('POST', '/v2/access-groups', payload=payload)
                click.echo("\nYour Access group {} is being created now \n".format(new_access_group['name']))
                click.echo("The UUID is {} \n".format(new_access_group['id']))
            else:
                update_group = request_data('PUT', '/v2/access-groups/' + str(answer), payload=payload)
                click.echo("\nYour Access group {} is being updated now \n".format(update_group['name']))
                click.echo("The UUID is {} \n".format(update_group['id']))
        except TypeError as E:
            click.echo("\nAccess group? - Check the Username")
            click.echo(E)
    else:
        click.echo("\nYour Tag was null. Check the spelling or perform a 'navi update assets'\n")
