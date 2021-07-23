import click
from .database import new_db_connection
from .api_wrapper import request_data, tenb_connection

tio = tenb_connection()


def check_agroup_exists(aname):
    rvalue = 'no'
    for group in tio.access_groups.list():
        if str(group['name']).lower() == str(aname).lower():
            rvalue = group['id']
    return rvalue


@click.command(help="Create an Access group Based on a Tag")
@click.option('--name', default='', required=True, help="Create an Access group with the following Name")
@click.option('--c', default='', required=True, help="Category name to use: requires --v and Value Name")
@click.option('--v', default='', required=True, help="Tag Value to use; requires --c and Category Name")
@click.option('--user', default='', help="User you want to Assign to the Access Group")
@click.option('--usergroup', default='', help="User Group you want to assign to the Access Group")
@click.option('-scan', is_flag=True, help="Set Scan ONLY permission")
@click.option('-view', is_flag=True, help="Set View ONLY permission")
@click.option('-scanview', is_flag=True, help="Set Scan AND View permissions")
def agroup(name, c, v, user, usergroup, scan, view, scanview):
    new_list = []
    permission = []
    choice = 'none'
    permtype = 'none'

    if user == '' and usergroup == '':
        click.echo("You Need to use '--user' or '--usergroup' command and supply a user or group. e.g: user@yourdomain or Linux Admins")
        exit()

    if user != '':
        permtype = 'user'
        choice = user

    if usergroup != '':
        permtype = 'group'
        choice = usergroup

    if name == '':
        click.echo("You need to use the --name command to name your Access Group")
        exit()

    if c == '':
        click.echo("Tag Category is required.  Please use the --c command")
        exit()

    if v == '':
        click.echo("Tag Value is required. Please use the --v command")
        exit()

    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT tag_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")
        assets = cur.fetchall()

        tag_uuid = assets[0]

        print(tag_uuid)

        if scanview:
            permission = ["CAN_VIEW", "CAN_SCAN"]

        if view:
            permission = ["CAN_VIEW"]

        if scan:
            permission = ["CAN_SCAN"]

        if not scan and not view and not scanview:
            click.echo("\nYou must supply a permission")
            click.echo("\nUse one of the following:\n-scan\n-view\n-scanview\n")
            exit()

        payload = {"name": str(name), "access_group_type": "MANAGE_ASSETS", "rules": [{"type": "tag_uuid", "operator": "set-has", "terms": tag_uuid}],
                   "principals": [{"permissions": permission, "type": permtype, "principal_name": choice}]}

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
