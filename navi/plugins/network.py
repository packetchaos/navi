import click
from .api_wrapper import request_data, tenb_connection
from .database import new_db_connection, db_query

# pytenable - No TTL Days / Change Age-out policy
tio = tenb_connection()


def get_scanner_id(scanner_name):
    # Receive name, convert to lower-case, then look up the scanner's ID
    for scanner in tio.scanners.list():
        if str(scanner_name).lower() == str(scanner['name']).lower():
            return scanner['uuid']
        else:
            return 'NONE'


def get_network_id(network_name):
    # Receive network name, convert to lower-case, then look up the network's uuid
    for net in tio.networks.list():
        if str(network_name).lower() == str(net['name']).lower():
            return network['uuid']
        else:
            return 'NONE'


@click.group(help="Create, Change Networks or Display Assets in a network")
def network():
    pass


@network.command(help="Change the Asset Age Out of a network")
@click.option("--age", default='', required=True, help="Change the Asset Age Out - 90days or more")
@click.option("--net", default='', required=True, help="Select Network ID")
def change(age, net):
    click.echo("\nChanging the age to {}\n".format(age))

    if age != '' and net != '' and len(net) == 36:
        if 1 <= int(age) <= 365:
            network_data = request_data('GET', '/networks/' + net)
            name = network_data['name']
            payload = {"assets_ttl_days": age, "name": name, "description": "TTL adjusted by navi"}
            request_data('PUT', '/networks/' + net, payload=payload)
        else:
            click.echo("Asset Age Out number must between 1 and 365")
    else:
        click.echo("Please enter a Age value and a network UUID")


@network.command(help="Create a new Network")
@click.option("--name", default='', required=True, help="Create a Network with the Following Name")
@click.option("--description", "--d", default='Navi Created', help="Create a description for your Network")
def new(name, description):
    click.echo("\nCreating a new network named {}\n".format(name))

    if name != '':
        tio.networks.create(name, description=description)


@network.command(help="Display Assets in a Network")
@click.option("--net", default='', required=True, help="Select Network ID")
def display(net):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT ip_address, fqdn, last_licensed_scan_date from assets where network == '" + net + "';")
        data = cur.fetchall()

        click.echo("\n{:25s} {:65s} {}".format("IP Address", "Full Qualified Domain Name", "Licensed Scan Date"))
        click.echo("-" * 150)
        click.echo()

        for asset in data:
            ipv4 = asset[0]
            fqdn = asset[1]
            licensed_date = asset[2]

            click.echo("{:25s} {:65s} {}".format(str(ipv4), str(fqdn), licensed_date))

    click.echo()


@network.command(help="Move a Scanner or Assets to a Network")
@click.option('--net', default='', required=True, help="Network Name or Network UUID")
@click.option('--scanner', default='', help="Scanner Name or Scanner UUID")
@click.option('--c', default='', help="Move Assets from This Tag Category")
@click.option('--v', default='', help="Move Assets from This Tag Value")
@click.option('--source', required=True, default='00000000-0000-0000-0000-000000000000', help="Source Network UUID")
@click.option('--target', default='', help="Move Assets by subnet(s)")
def move(net, scanner, c, v, source, target):
    ip_list = ""
    if scanner != '':
        # Here I just want to check to see if its a uuid. If it's not 36 chars long, its not a uuid.
        if len(net) != 36:
            network_id = get_network_id(net)
        else:
            network_id = net

        # Scanner UUIDs have two lengths, both over 35. This isn't bullet proof but it's good enough for now.
        # I expect a lot from users. :)
        if len(scanner) > 35:
            # This should be a uuid.
            scanner_id = scanner
        else:
            # Lets grab the uuid
            scanner_id = get_scanner_id(scanner)

        # move the scanner
        tio.networks.assign_scanners(network_id, scanner_id)

    if c != '' and v != '':
        # First grab all of the UUIDS in the tag and put them in a list
        click.echo("\nThis feature is limited to 1999 assets; Consider using 'target' option to specify a subnet\n")
        tag_uuid_list = []
        tag_data = db_query("SELECT asset_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")
        for uuid in tag_data:
            if uuid not in tag_uuid_list:
                tag_uuid_list.append(uuid[0])

        # then grab the Scanned IP from the vulns table using the UUID as a Key; then put the IPs in a list
        ip_list = ""
        for item in tag_uuid_list:
            ip_address = db_query("select asset_ip from vulns where asset_uuid='{}'".format(item))

            try:
                ip = ip_address[0][0]
                if ip not in ip_list:
                    ip_list = ip_list + "," + ip
            except IndexError:
                pass

    if target:
        ip_list = ip_list + "," + target

    # Current limit is 1999 assets to be moved at once
    payload = {"source": source, "destination": net, "targets": ip_list[1:]}
    request_data("POST", '/api/v2/assets/bulk-jobs/move-to-network', payload=payload)
    click.echo("\nMoving these assets \n {}".format(ip_list[1:]))
