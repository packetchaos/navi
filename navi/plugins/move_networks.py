import click
from .api_wrapper import tenb_connection

tio = tenb_connection()


def get_scanner_id(scanner_name):
    # Receive name, convert to lower-case, then look up the scanner's ID
    for scanner in tio.scanners.list():
        if str(scanner_name).lower() == str(scanner_name['name']).lower():
            return scanner['uuid']
        else:
            return 'NONE'


def get_network_id(network_name):
    # Receive network name, convert to lower-case, then look up the network's uuid
    for network in tio.networks.list():
        if str(network_name).lower() == str(network['name']).lower():
            return network['uuid']
        else:
            return 'NONE'


@click.command(help="Move Assets or Scanners to a New Network")
@click.option('--network', default='', help="Network Name or Network UUID")
@click.option('--scanner', default='', help="Scanner Name or Scanner UUID")
def move(network, scanner):

    if network != '' and  scanner != '':
        # Here I just want to check to see if its a uuid. If it's not 36 chars long, its not a uuid.
        if len(network) != 35:
            network_id = get_network_id(network)
        else:
            network_id = network

        # Scanner UUIDs have two lengths, both over 35. This isn't bullet proof but it's good enough for now.
        # I expect a lot from users. :)
        if len(scanner) > 30:
            # This should be a uuid.
            scanner_id = scanner
        else:
            # Lets grab the uuid
            scanner_id = get_scanner_id(scanner)

        # move the scanner
        tio.networks.assign_scanners(network_id, scanner_id)

    else:
        click.echo("You need to provide a Scanner and a Network. Either by name or by UUID")
