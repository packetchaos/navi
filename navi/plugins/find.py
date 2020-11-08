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
            cur.execute("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON asset_uuid = uuid where plugin_id=%s" % pid)

            rows = cur.fetchall()

            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)
            for row in rows:
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(pid), row[0], textwrap.shorten(row[2], 46), row[1], row[3]))

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
        if output != "":
            try:
                plugin_db = r"navi.db"
                plugin_conn = new_db_connection(plugin_db)
                with plugin_conn:
                    click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
                    click.echo("-" * 150)
                    plugin_cur = plugin_conn.cursor()
                    plugin_cur.execute("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON asset_uuid = uuid where plugin_id='" + plugin_id + "' and output LIKE '%" + output + "%';")
                    plugin_data = plugin_cur.fetchall()
                    for row in plugin_data:
                        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(plugin_id), row[0], textwrap.shorten(row[2], 46), row[1], row[3]))
            except Error:
                pass
        else:
            find_by_plugin(plugin_id)


@find.command(help="Find Assets where Text was found in the output of any plugin")
@click.argument('out_put')
def output(out_put):
    try:
        plugin_db = r"navi.db"
        plugin_conn = new_db_connection(plugin_db)
        with plugin_conn:
            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)
            plugin_cur = plugin_conn.cursor()
            plugin_cur.execute("SELECT asset_ip, asset_uuid, fqdn, network, plugin_id from vulns LEFT JOIN assets ON asset_uuid = uuid where output LIKE '%" + str(out_put) + "%';")
            plugin_data = plugin_cur.fetchall()
            for row in plugin_data:
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[4], row[0], textwrap.shorten(row[2], 46), row[1], row[3]))
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
    print("\nPotential Web Applications Report\n")
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT output, asset_uuid, asset_ip, network FROM vulns LEFT JOIN assets ON asset_uuid = uuid where plugin_id ='12053';")

        rows = cur.fetchall()

        for row in rows:
            host = row[0].split()
            final_host = host[3][:-1]
            uuid = row[1]
            print()
            print("*" * 50)
            print("Asset IP: {}".format(row[2]))
            print("Asset UUID: {}".format(row[1]))
            print("Network UUID: {}".format(row[3]))
            print("*" * 50)
            cur2 = conn.cursor()
            cur2.execute("SELECT output, port FROM vulns where plugin_id ='22964' and asset_uuid='{}';".format(uuid))
            new_row = cur2.fetchall()
            print("\nWeb Apps Found")
            print("-" * 14)
            for service in new_row:

                if "web" in service[0]:

                    if "through" in service[0]:
                        print("https://{}:{}".format(final_host, service[1]))
                    else:
                        print("http://{}:{}".format(final_host, service[1]))

            cur3 = conn.cursor()
            cur3.execute("SELECT output, port FROM vulns where plugin_id ='93561' and asset_uuid='{}';".format(uuid))
            doc_row = cur3.fetchall()
            if doc_row:
                print("\nThese web apps might be running on one or more of these containers:\n")
            for doc in doc_row:
                plug = doc[0].splitlines()
                for x in plug:
                    if "Image" in x:
                        print(x)
                    if "Port" in x:
                        print(x)
                        print()
            print("-" * 100)


@find.command(help="Find Assets with Credential Issues using plugin 104410")
def creds():
    click.echo("\nBelow are the Assets that have had Credential issues\n")
    find_by_plugin(104410)


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
        cur.execute("SELECT plugin_id, asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON asset_uuid = uuid where port=" + open_port + " and (plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

        data = cur.fetchall()

        try:
            click.echo("\nThe Following assets had Open ports found by various plugins")

            click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "UUID", "Network UUID"))
            click.echo("-" * 150)

            for vulns in data:
                click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(vulns[0]), vulns[1], textwrap.shorten(vulns[3], 46), vulns[2], vulns[4]))

            click.echo()
        except ValueError:
            pass


@find.command(help="Find Assets through a SQL query.")
@click.argument('statement')
def query(statement):
    database = r"navi.db"
    query_conn = new_db_connection(database)
    with query_conn:

        cur = query_conn.cursor()
        cur.execute(statement)

        data = cur.fetchall()
        pprint.pprint(data)


@find.command(help="Find Assets with a given name")
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
            click.echo("\n{:8s} {:20} {:45} {:70} ".format("Plugin", "IP address", "UUID", "Plugin Name"))
            click.echo("-" * 150)
            for vulns in plugin_data:
                click.echo("{:8s} {:20} {:45} {:70}".format(vulns[3], vulns[0], str(vulns[1]), textwrap.shorten(str(vulns[2]), 65)))
            click.echo()
    except Error:
        pass
