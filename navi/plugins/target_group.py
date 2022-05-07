import click
from .api_wrapper import request_data
from IPy import IP


def find_target_group(tg_name):

    data = request_data("GET", '/target-groups')
    group_id = 0
    for group in data['target_groups']:
        try:
            if group['name'] == tg_name:
                group_id = group['id']
        except KeyError:
            pass
    return group_id


def create_target_group(target_name, tg_list):

    # Check to see if the Target group exists
    group_id = find_target_group(target_name)

    # Target group API takes a string of IPs. We will start the string here.
    trgstring = ""

    # Check to see if tg_list is a string
    string_test = isinstance(tg_list, str)

    # turn the list into a string separated by a comma
    if not string_test:
        for ips in tg_list:
            trgstring = trgstring + str(ips) + ","
    else:
        trgstring = tg_list

    if not tg_list:
        click.echo("\nYour request returned zero results\nAs a result, nothing happened\n")
        exit()

    click.echo("\nThese are the IPs that will be added to the target Group: {}".format(target_name))
    click.echo(tg_list)
    click.echo()

    if group_id != 0:
        # Update current Target Group
        payload = {"name": target_name, "members": trgstring, "type": "system"}
        request_data("PUT", '/target-groups/'+str(group_id), payload=payload)
    else:
        # Create a New Target Group
        payload = {"name": target_name, "members": str(trgstring), "type": "system", "acls": [{"type": "default", "permissions": 64}]}
        request_data("POST", '/target-groups', payload=payload)


def cloud_to_target_group(cloud, days, choice, target_group_name):
    query = {"date_range": days, "filter.0.filter": "sources", "filter.0.quality": "set-has", "filter.0.value": cloud}
    data = request_data('GET', '/workbenches/assets', params=query)
    target_ips = []

    for assets in data['assets']:
        target_ip_list = assets['ipv4']
        # loop through all of the IPs
        for ip in target_ip_list:
            # Check to IP type
            check_ip = IP(ip)
            check = check_ip.iptype()
            if check == choice:
                # Add the IP if there is a match
                target_ips.append(ip)

    create_target_group(target_group_name, target_ips)


@click.group(help="Migrate Target Groups to Scans or Tags and Create Target Groups(Retiring soon)")
def tgroup():
    pass


@tgroup.command(help="Create a Target Group - Retiring in T.io soon")
@click.option('--name', default='', required=True, help="Target Group Name")
@click.option('--ip', default='', help="Ip(s) or subnet(s) separated by coma")
@click.option('-aws', is_flag=True, help="Turn AWS assets found by the connector into a Target Group")
@click.option('-gcp', is_flag=True, help="Turn GCP assets found by the connector into a Target Group")
@click.option('-azure', is_flag=True, help="Turn Azure assets found by the connector into a Target Group")
@click.option('--days', default='30', help="Set the number of days for the IPs found by the connector. Requires: aws, gcp, or azure")
@click.option('-priv', is_flag=True, help="Set the IP(s) to be used as Private")
@click.option('-pub', is_flag=True, help="Set the IP to be used as Public")
def create(name, ip, aws, gcp, azure, days, priv, pub):
    choice = 'PUBLIC'

    if priv:
        choice = 'PRIVATE'

    if pub:
        choice = 'PUBLIC'

    if ip != '':
        create_target_group(name, ip)

    if aws:
        cloud_to_target_group("AWS", days, choice, name)

    if gcp:
        cloud_to_target_group("GCP", days, choice, name)

    if azure:
        cloud_to_target_group("AZURE", days, choice, name)


@tgroup.command(help="Migrate Target Groups to Tags or to Scan Text Targets")
@click.option('--scan', default='', help="Move Target Group Members in a given scan to the Text Target section of the same scan")
@click.option('-tags', is_flag=True, help="Migrate All Target Groups to Tags - Target Group Type : Target Group Name")
def migrate(scan, tags):

    if tags:
        tgroups = request_data('GET', '/target-groups')

        for group in tgroups['target_groups']:
            member = group['members']
            name = group['name']
            group_type = group['type']
            d = "Imported by Script"
            try:
                if name != 'Default':
                    payload = {"category_name": str(group_type), "value": str(name), "description": str(d), "filters":
                              {"asset": {"and": [{"field": "ipv4", "operator": "eq", "value": str(member)}]}}}
                    data = request_data('POST', '/tags/values', payload=payload)

                    value_uuid = data["uuid"]
                    cat_uuid = data['category_uuid']
                    print("\nI've created your new Tag - {} : {}\n".format(group_type, name))
                    print("The Category UUID is : {}\n".format(cat_uuid))
                    print("The Value UUID is : {}\n".format(value_uuid))
            except TypeError:
                click.echo("\nTag has already been created, or there was a name conflict\n")
                pass

    elif scan:
        def grab_tg_members():
            # Grab all members of every target group and put them into a dict for evaluation later
            tg_member_dict = {}
            member_data = request_data('GET', '/target-groups')

            for tg in member_data['target_groups']:
                tg_member = tg['members']
                tg_member_dict[tg['id']] = tg_member
            return tg_member_dict

        def get_tg_list():
            # grab the target list ID from a scan
            tgs_for_scan = []
            tg_data = request_data("GET", '/editor/scan/{}'.format(scan))
            for item in tg_data["settings"]["basic"]["inputs"]:
                if item["name"] == "Target Groups":
                    tgs_for_scan = item["default"]  # This maps each scan ID to the list of target group IDs
            return tgs_for_scan

        text_target_string = ""
        try:
            for scan_id in get_tg_list():
                text_target_string = text_target_string + ",{}".format(grab_tg_members()[scan_id])

            payload = {"settings": {
                       "target_groups": [],
                       "text_targets": text_target_string[1:]}}

            update_scan = request_data("PUT", "/scans/{}".format(scan), payload=payload)
            click.echo("\n{} was updated with the below targets:\n {}".format(update_scan['name'], text_target_string[1:]))
        except TypeError:
            exit()
        except KeyError:
            click.echo("\nScan doesn't exist or doesn't have a target group assigned\n")
    else:
        click.echo("\nYou need to select an option: --scan or -tags\n")
