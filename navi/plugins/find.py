import click
import pprint
from .api_wrapper import tenb_connection
from .database import db_query
import textwrap


tio = tenb_connection()


def find_by_plugin(pid):
    rows = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON asset_uuid = uuid where plugin_id=%s" % pid)

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    for row in rows:
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(pid), row[0], textwrap.shorten(row[2], 46), row[1], row[3]))

    click.echo()


@click.group(help="Discover assets with Open ports, Running containers and more")
def find():
    pass


@find.command(help="Find Assets where a plugin fired using the plugin ID")
@click.argument('plugin_id')
@click.option('--o', '--output', default='', help='Find Assets based on the text in the output')
def plugin(plugin_id, o):
    if not str.isdigit(plugin_id):
        click.echo("You didn't enter a number")
        exit()
    else:
        if o != "":
            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)

            plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON "
                                   "asset_uuid = uuid where plugin_id='" + plugin_id + "' and output LIKE '%" + o + "%';")

            for row in plugin_data:
                try:
                    fqdn = row[2]
                except:
                    fqdn = " "
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(plugin_id), row[0], textwrap.shorten(fqdn, 46), row[1], row[3]))

        else:
            find_by_plugin(plugin_id)


@find.command(help="Find Assets that have a given CVE iD")
@click.argument('cve_id')
def cve(cve_id):

    if len(cve_id) < 10:
        click.echo("\nThis is likely not a CVE...Try again...\n")

    elif "CVE" not in cve_id:
        click.echo("\nYou must have 'CVE' in your CVE string. EX: CVE-1111-2222\n")

    else:
        click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, plugin_id, network from vulns LEFT JOIN "
                               "assets ON asset_uuid = uuid where cves LIKE '%" + cve_id + "%';")

        for row in plugin_data:
            try:
                fqdn = row[2]
            except:
                fqdn = " "
            click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[3], row[0], textwrap.shorten(fqdn, 46), row[1], row[4]))

        click.echo()


@find.command(help="Find Assets that have an exploitable vulnerability")
def exploit():

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, plugin_id, network from vulns LEFT JOIN"
                           " assets ON asset_uuid = uuid where exploit = 'True';")

    for row in plugin_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[3], row[0], textwrap.shorten(fqdn, 46), row[1], row[4]))

    click.echo()


@find.command(help="Find Assets where Text was found in the output of any plugin")
@click.argument('out_put')
def output(out_put):

    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network, plugin_id from vulns LEFT JOIN"
                           " assets ON asset_uuid = uuid where output LIKE '%" + str(out_put) + "%';")

    for row in plugin_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[4], row[0], textwrap.shorten(fqdn, 46), row[1], row[3]))

    click.echo()


@find.command(help="Find Docker Hosts using plugin 93561")
def docker():
    click.echo("Searching for RUNNING docker containers...")
    find_by_plugin(str(93561))


@find.command(help="Find Potential Web Apps using plugin 1442 and 22964")
def webapp():

    click.echo("\nPotential Web Applications Report\n")

    rows = db_query("SELECT output, asset_uuid, asset_ip, network FROM vulns LEFT JOIN"
                    " assets ON asset_uuid = uuid where plugin_id ='12053';")

    for row in rows:
        host = row[0].split()
        final_host = host[3][:-1]
        uuid = row[1]

        click.echo("*" * 50)
        click.echo("Asset IP: {}".format(row[2]))
        click.echo("Asset UUID: {}".format(row[1]))
        click.echo("Network UUID: {}".format(row[3]))
        click.echo("*" * 50)

        new_row = db_query("SELECT output, port FROM vulns where plugin_id ='22964' and asset_uuid='{}';".format(uuid))
        click.echo("\nWeb Apps Found")
        click.echo("-" * 14)

        for service in new_row:
            if "web" in service[0]:
                if "through" in service[0]:
                    click.echo("https://{}:{}".format(final_host, service[1]))
                else:
                    click.echo("http://{}:{}".format(final_host, service[1]))

        doc_row = db_query("SELECT output, port FROM vulns where plugin_id ='93561' and asset_uuid='{}';".format(uuid))

        if doc_row:
            click.echo("\nThese web apps might be running on one or more of these containers:\n")

        for doc in doc_row:
            plug = doc[0].splitlines()
            for x in plug:
                if "Image" in x:
                    click.echo(x)
                if "Port" in x:
                    click.echo(x)
                    click.echo()
        click.echo("-" * 100)


@find.command(help="Find Assets with Credential Issues using plugin 104410")
def creds():
    click.echo("\nBelow are the Assets that have had Credential issues\n")
    find_by_plugin(104410)


@find.command(help="Find Assets that took longer than a given set of minutes to complete")
@click.argument('minute')
def scantime(minute):

    click.echo("\n*** Below are the assets that took longer than {} minutes to scan ***".format(str(minute)))

    data = db_query("SELECT asset_ip, asset_uuid, scan_started, scan_completed, scan_uuid, output from vulns where plugin_id='19506';")

    try:
        click.echo("\n{:16s} {:40s} {:25s} {:25s} {}".format("Asset IP", "Asset UUID", "Started", "Finished", "Scan UUID"))
        click.echo("-" * 150)
        for vulns in data:

            plugin_output = vulns[5]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            # grab the length so we can grab the seconds
            length = len(parsed_output)

            # grab the scan duration- second to the last variable
            duration = parsed_output[length - 2]

            # Split at the colon to grab the numerical value
            seconds = duration.split(" : ")

            # split to remove "secs"
            number = seconds[1].split(" ")

            # grab the number for our minute calculation
            final_number = number[0]

            if final_number != 'unknown':
                # convert seconds into minutes
                minutes = int(final_number) / 60

                # grab assets that match the criteria
                if minutes > int(minute):
                    try:
                        click.echo("{:16s} {:40s} {:25s} {:25s} {}".format(str(vulns[0]), str(vulns[1]),
                                                                           str(vulns[2]), str(vulns[3]),
                                                                           str(vulns[4])))
                    except ValueError:
                        pass
        click.echo()
    except Exception as E:
        print(E)


@find.command(help="Find Assets that have not been scanned in any Cloud")
def ghost():
    click.echo("\n{:11s} {:15s} {:50} {}".format("Source", "IP", "FQDN", "First seen"))
    click.echo("-" * 150)

    for assets in tio.workbenches.assets(("sources", "set-hasonly", "AWS")):
        for source in assets['sources']:
            if source['name'] == 'AWS':
                try:
                    aws_ip = assets['ipv4'][0]
                except IndexError:
                    aws_ip = "No IP Found"
                try:
                    aws_fqdn = assets['fqdn'][0]
                except IndexError:
                    aws_fqdn = "No FQDN Found"

                click.echo("{:11s} {:15s} {:50} {}".format(str(source['name']), str(aws_ip),
                                                           str(aws_fqdn), source['first_seen']))
    click.echo()

    for gcp_assets in tio.workbenches.assets(("sources", "set-hasonly", "GCP")):
        for gcp_source in gcp_assets['sources']:
            if gcp_source['name'] == 'GCP':
                try:
                    gcp_ip = gcp_assets['ipv4'][0]
                except IndexError:
                    gcp_ip = "No IP Found"
                try:
                    gcp_fqdn = gcp_assets['fqdn'][0]
                except IndexError:
                    gcp_fqdn = "NO FQDN FOUND"

                click.echo("{:11s} {:15s} {:50} {}".format(gcp_source['name'], gcp_ip, gcp_fqdn,
                                                           gcp_source['first_seen']))
    click.echo()

    for az_assets in tio.workbenches.assets(("sources", "set-hasonly", "AZURE")):
        for az_source in az_assets['sources']:
            if az_source['name'] == 'AZURE':
                try:
                    az_ip = az_assets['ipv4'][0]
                except IndexError:
                    az_ip = "No IP Found"

                try:
                    az_fqdn = az_assets['fqdn'][0]
                except IndexError:
                    az_fqdn = "NO FQDN Found"

                click.echo("{:11s} {:15s} {:50} {}".format(az_source['name'], az_ip, az_fqdn,
                                                           az_source['first_seen']))
    click.echo()


@find.command(help="Find Assets with a given port open")
@click.argument('open_port')
def port(open_port):
    data = db_query("SELECT plugin_id, asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN "
                    "assets ON asset_uuid = uuid where port=" + open_port + " and "
                    "(plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

    try:
        click.echo("\nThe Following assets had Open ports found by various plugins")
        click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
        click.echo("-" * 150)

        for vulns in data:
            try:
                fqdn = vulns[3]
            except:
                fqdn = " "

            click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(vulns[0]), vulns[1], textwrap.shorten(fqdn, 46),
                                                              vulns[2], vulns[4]))

        click.echo()
    except ValueError:
        pass


@find.command(help="Find Assets using a custom SQL query.")
@click.argument('statement')
def query(statement):
    data = db_query(statement)
    pprint.pprint(data)


@find.command(help="Find Assets where a plugin fired with TEXT found in a plugin name")
@click.argument('plugin_name')
def name(plugin_name):

    plugin_data = db_query("SELECT asset_ip, asset_uuid, plugin_name, plugin_id from vulns where plugin_name LIKE '%" + plugin_name + "%';")

    click.echo("\nThe Following assets had '{}' in the Plugin Name".format(plugin_name))
    click.echo("\n{:8s} {:20} {:45} {:70} ".format("Plugin", "IP address", "UUID", "Plugin Name"))
    click.echo("-" * 150)

    for vulns in plugin_data:
        click.echo("{:8s} {:20} {:45} {:70}".format(vulns[3], vulns[0], str(vulns[1]), textwrap.shorten(str(vulns[2]), 65)))

    click.echo()


@find.command(help="Find Assets that have a Cross Reference Type and/or ID")
@click.argument('xref')
@click.option("--xid", "--xref-id", default='', help="Specify a Cross Reference ID")
def xrefs(xref, xid):
    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
    click.echo("-" * 150)

    if xid:
        xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                             " assets ON asset_uuid = uuid where xrefs LIKE '%{}%' AND xrefs LIKE '%{}%'".format(xref, xid))

    else:
        xref_data = db_query("select plugin_id, asset_ip, fqdn, asset_uuid, network, xrefs from vulns LEFT JOIN"
                             " assets ON asset_uuid = uuid where xrefs LIKE '%{}%'".format(xref))

    for row in xref_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "

        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[0], row[1], textwrap.shorten(fqdn, 46), row[3], row[4]))

    click.echo()
