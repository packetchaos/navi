import click
from .api_wrapper import request_data, tenb_connection
from .database import new_db_connection

# pytenable - No TTL Days / Change Age-out policy
tio = tenb_connection()


@click.group(help="Create, Change Networks or Display Assets in a network")
def network():
    pass


@network.command()
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


@network.command()
@click.option("--name", default='', required=True, help="Create a Network with the Following Name")
@click.option("--description", "--d", default='Navi Created', help="Create a description for your Network")
def new(name, description):
    click.echo("\nCreating a new network named {}\n".format(name))

    if name != '':
        tio.networks.create(name, description=description)


@network.command()
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
