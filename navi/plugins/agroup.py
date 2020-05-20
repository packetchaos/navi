import click
from .database import new_db_connection
from .api_wrapper import request_data


def check_agroup_exists(aname):
    agroups = request_data('GET', '/access-groups')
    rvalue = 'no'
    for group in agroups['access_groups']:
        if str(group['name']).lower() == str(aname).lower():
            rvalue = group['id']
    return rvalue


@click.command(help="Create an Access group Based on a Tag or Agent Group")
@click.option('--name', default='', help="Create an Access group with the following Name")
@click.option('-tag', is_flag=True, help="Create a Access Group by a Tag")
@click.option('--c', default='', help="Category name to use")
@click.option('--v', default='', help="Tag Value to use; requires --c and Category Name")
@click.option('--group', default='', help="Create a Tag based on a Agent Group")
def agroup(name, tag, c, v, group):
    new_list = []

    if name == '':
        print("You need to use the --name command to name your Access Group")
        exit()

    if tag:
        if c == '':
            print("Tag Category is required.  Please use the --c command")
            exit()

        if v == '':
            print("Tag Value is required. Please use the --v command")
            exit()

        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:

            cur = conn.cursor()
            cur.execute("SELECT asset_uuid, asset_ip from tags where tag_key='" + c + "' and tag_value='" + v + "';")

            assets = cur.fetchall()

            for asset in assets:
                new_list.append(asset[1])

    if group:
        querystring = {"limit": "5000"}
        group_data = request_data('GET', '/scanners/1/agent-groups')
        for agent_group in group_data['groups']:
            group_name = agent_group['name']
            group_id = agent_group['id']

            if group_name == group:
                data = request_data('GET', '/scanners/1/agent-groups/' + str(group_id) + '/agents', params=querystring)

                for agent in data['agents']:
                    ip_address = agent['ip']
                    new_list.append(ip_address)

    payload = {"name": str(name), "access_group_type": "MANAGE_ASSETS", "all-users": True, "rules": [{"type": "ipv4", "operator": "eq", "terms": new_list}]}

    answer = check_agroup_exists(str(name))

    if answer == 'no':
        new_access_group = request_data('POST', '/v2/access-groups', payload=payload)
        print("\nYour Access group {} is being created now \n".format(new_access_group['name']))
        print("The UUID is {} \n".format(new_access_group['id']))
    else:
        update_group = request_data('PUT', '/v2/access-groups/' + str(answer), payload=payload)
        print("\nYour Access group {} is being updated now \n".format(update_group['name']))
        print("The UUID is {} \n".format(update_group['id']))

