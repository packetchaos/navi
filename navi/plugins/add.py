from sqlite3 import Error
import click
from .add_helper import add_helper
from .api_wrapper import request_data
from .error_msg import error_msg


@click.command(help="Manually add an asset to Tenable.io")
@click.option('--ip', default='', help="IP address(s) of new asset")
@click.option('--mac', default='', help="Mac Address of new asset")
@click.option('--netbios', default='', help="NetBios of new asset")
@click.option('--fqdn', default='', help='FQDN of new asset')
@click.option('--hostname', default='', help="Hostname of new asset")
@click.option('--file', default='', help="Provide a CSV file in this order: IP, MAC, FQDN, Hostname. Leave fields blank if N/A")
@click.option('--source', default='navi', help="Provide the source of the information")
def add(ip, mac, netbios, fqdn, hostname, file, source):
    try:
        asset = {}
        ipv4 = []
        macs = []
        fqdns = []
        hostnames = []
        if ip:
            ipv4.append(ip)
            asset["ip_address"] = ipv4

        if mac:
            macs.append(mac)
            asset["mac_address"] = macs

        if netbios:
            asset["netbios_name"] = netbios

        if fqdn:
            fqdns.append(fqdn)
            asset["fqdn"] = fqdns

        if hostname:
            hostnames.append(hostname)
            asset["hostname"] = hostnames

        if file:
            add_helper(file, source)

        if asset:
            # create Payload
            payload = {"assets": [asset], "source": source}

            click.echo("Adding the following Data : \n{}\n".format(payload))

            # request Import Job
            data = request_data('POST', '/import/assets', payload=payload)
            click.echo("Your Import ID is : {}".format(data['asset_import_job_uuid']))
        else:
            click.echo("\nYou need to supply some information\n")
    except Error:
        click.echo("\nCheck your permissions or your API keys\n")
