import click
from .api_wrapper import request_data, tenb_connection
from .database import new_db_connection

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
@click.option("--age", default='', required=True, help="Change the Asset Age Out")
@click.option("--net", default='', required=True, help="Select Network ID")
def change(age, net):
    click.echo("\nChanging the age to  {}\n".format(age))

    if age != '' and net != '' and len(net) == 36:
        network_data = request_data('GET', '/networks/' + net)
        name = network_data['name']

        payload = {"assets_ttl_days": age, "name": name, "description": "TTL adjusted by navi"}
        request_data('PUT', '/networks/' + net, payload=payload)

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


@network.command(help="Move Assets or Scanners to a New Network")
@click.option('--net', default='', help="Network Name or Network UUID")
@click.option('--scanner', default='', help="Scanner Name or Scanner UUID")
def move(net, scanner):
    if net != '' and scanner != '':
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

    else:
        click.echo("You need to provide a Scanner and a Network. Either by name or by UUID")
