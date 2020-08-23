import click
from sqlite3 import Error
import pprint
from .api_wrapper import tenb_connection
from .database import new_db_connection
import textwrap


tio = tenb_connection()


def find_by_plugin(pid):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id=%s;" % pid)

            rows = cur.fetchall()

            for row in rows:
                ip = row[0]
                uuid = row[1]
                find_output = row[2]
                click.echo("\nIP Address: {}".format(ip))
                click.echo("UUID : {}".format(uuid))
                click.echo("\n--- Plugin {} Output ---".format(pid))
                click.echo()
                click.echo(find_output)
                click.echo("--- End plugin Output ---")
    except Error as e:
        click.echo(e)


@click.group(help="Discover what is in Tenable.io")
def find():
    pass


@find.command(help="Find Assets where a plugin fired")
@click.argument('plugin_id')
@click.option('--output', default='', help='Find Assets based on the text in the output')
def plugin(plugin_id, output):
    if not str.isdigit(plugin_id):
        click.echo("You didn't enter a number")
        exit()
    else:
        try:
            plugin_db = r"navi.db"
            plugin_conn = new_db_connection(plugin_db)
            with plugin_conn:
                plugin_cur = plugin_conn.cursor()
                # See if we want to refine our search by the output found in this plugin
                # this needs to have a JOIN statement to reduce the amount of IPs
                if output != "":
                    plugin_cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id='" + plugin_id + "' and output LIKE '%" + output + "%';")
                else:
                    find_by_plugin(plugin_id)

                plugin_data = plugin_cur.fetchall()
                for x in plugin_data:
                    asset_ip = x[0]
                    asset_output = x[2]
                    click.echo(asset_ip)
                    click.echo('*' * 20)
                    click.echo(asset_output)
                    click.echo('*' * 150)
                    click.echo('*' * 150)
        except Error:
            pass


@find.command(help="Find Docker Hosts using plugin 93561")
def docker():
    click.echo("Searching for RUNNING docker containers...")
    find_by_plugin(str(93561))


@find.command(help="Find Potential Web Apps using plugin 1442 and 22964")
def webapp():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * from vulns where plugin_id='1442';")

        data = cur.fetchall()
        click.echo("\nWeb Servers found by plugin 1442")
        click.echo("-------------------------------")
        for plugins in data:
            web = plugins[6]  # output
            wsplit = web.split("\n")

            server = wsplit[1]
            web_port = plugins[10]  # port number
            proto = plugins[11]  # Protocol
            asset = plugins[1]  # Ip address
            click.echo()
            click.echo("{} is running on: {} / {} On : {}".format(str(server), str(web_port), str(proto), str(asset)))
            click.echo()
    try:
        click.echo("\n\nWeb Servers/SSH Servers found by plugin '22964';")
        click.echo("-" * 32)
        click.echo()
        conn2 = new_db_connection(database)
        with conn2:
            cur2 = conn.cursor()
            cur2.execute("SELECT output, port, asset_ip from vulns where plugin_id='22964'")
            data = cur2.fetchall()

            for plugins in data:
                web_output = plugins[0][:-1]
                web_port = plugins[1]
                web_ip = plugins[2]
                click.echo("{} {} On : {}".format(str(web_output), str(web_port), str(web_ip)))
            click.echo()
    except IndexError:
        click.echo("No information for plugin 22964")


@find.command(help="Find Assets with Credential Issues using plugin 104410")
def creds():
    click.echo("I'm looking for credential issues...Please hang tight")
    find_by_plugin(str(104410))


@find.command(help="Find Assets where a plugin fired")
@click.argument('minute')
def scantime(minute):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        click.echo("\n*** Below are the assets that took longer than {} minutes to scan ***".format(str(minute)))
        cur = conn.cursor()
        cur.execute("SELECT * from vulns where plugin_id='19506';")

        data = cur.fetchall()
        try:
            click.echo("\n{:16s} {:40s} {:25s} {:25s} {}".format("Asset IP", "Asset UUID", "Started", "Finished", "Scan UUID"))
            click.echo("-" * 150)
            for vulns in data:

                output = vulns[6]

                # split the output by return
                parsed_output = output.split("\n")

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

                # convert seconds into minutes
                minutes = int(final_number) / 60

                # grab assets that match the criteria
                if minutes > int(minute):
                    try:
                        click.echo("{:16s} {:40s} {:25s} {:25s} {}".format(str(vulns[1]), str(vulns[2]),
                                                                           str(vulns[14]), str(vulns[13]),
                                                                           str(vulns[15])))
                    except ValueError:
                        pass
            click.echo()
        except ValueError:
            pass


@find.command(help="Find Assets that have not been scanned in any Cloud")
def ghost():
    try:
        click.echo("\n{:11s} {:15s} {:45} {}".format("Source", "IP", "FQDN", "First seen"))
        click.echo("-" * 150)
        for assets in tio.workbenches.assets(("sources", "set-hasonly", "AWS")):
            for source in assets['sources']:
                if source['name'] == 'AWS':
                    aws_ip = assets['ipv4'][0]
                    try:
                        aws_fqdn = assets['fqdn'][0]
                    except IndexError:
                        aws_fqdn = assets['fqdn'][0]

                    click.echo("{:11s} {:15s} {:45} {}".format(str(source['name']), str(aws_ip),
                                                               str(aws_fqdn), source['first_seen']))
        click.echo()

        for gcp_assets in tio.workbenches.assets(("sources", "set-hasonly", "GCP")):
            for gcp_source in gcp_assets['sources']:
                if gcp_source['name'] == 'GCP':
                    gcp_ip = gcp_assets['ipv4'][0]
                    try:
                        gcp_fqdn = gcp_assets['fqdn'][0]
                    except IndexError:
                        gcp_fqdn = "NO FQDN FOUND"

                    click.echo("{:11s} {:15s} {:45} {}".format(gcp_source['name'], gcp_ip, gcp_fqdn,
                                                               gcp_source['first_seen']))
        click.echo()

        for az_assets in tio.workbenches.assets(("sources", "set-hasonly", "AZURE")):
            for az_source in az_assets['sources']:
                if az_source['name'] == 'AZURE':

                    az_ip = az_assets['ipv4'][0]
                    try:
                        az_fqdn = az_assets['fqdn'][0]
                    except IndexError:
                        az_fqdn = "NO FQDN Found"

                    click.echo("{:11s} {:15s} {:45} {}".format(az_source['name'], az_ip, az_fqdn,
                                                               az_source['first_seen']))
        click.echo()

    except Exception as E:
        click.echo("Check your API keys or your internet connection")
        click.echo(E)


@find.command(help="Find Assets with a given port open")
@click.argument('open_port')
def port(open_port):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * from vulns where port=" + open_port + " and (plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

        data = cur.fetchall()

        try:
            click.echo("\nThe Following assets had Open ports found by various plugins")
            click.echo("\n{:20} {:45} {}".format("IP address", " UUID", " Plugins"))
            click.echo("-" * 80)
            for vulns in data:
                click.echo("{:20} {:45} {}".format(vulns[1], str(vulns[2]), vulns[7]))
            click.echo()
        except ValueError:
            pass


@find.command(help="Find Assets with a given port open")
@click.argument('statement')
def query(statement):
    database = r"navi.db"
    query_conn = new_db_connection(database)
    with query_conn:

        cur = query_conn.cursor()
        cur.execute(statement)

        data = cur.fetchall()
        pprint.pprint(data)


@find.command(help="Find Assets with a given port open")
@click.argument('plugin_name')
def name(plugin_name):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_ip, asset_uuid, plugin_name, plugin_id from vulns where plugin_name LIKE '%" + plugin_name + "%';")

            plugin_data = cur.fetchall()
            click.echo("\nThe Following assets had '{}' in the Plugin Name".format(plugin_name))
            click.echo("\n{:20} {:45} {:65} {}".format("IP address", "UUID", "Plugin Name", "Plugin ID"))
            click.echo("-" * 150)
            for vulns in plugin_data:
                click.echo("{:20} {:45} {:65} {}".format(vulns[0], str(vulns[1]), textwrap.shorten(str(vulns[2]), 65), vulns[3]))
            click.echo()
    except Error:
        pass
