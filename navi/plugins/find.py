import click
from sqlite3 import Error
import pprint
from .api_wrapper import request_data
from .database import new_db_connection
import textwrap


def find_by_plugin(plugin):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id=%s;" % plugin)

            rows = cur.fetchall()

            for row in rows:
                print("\nIP Address: " + row[0])
                print("UUID : " + row[1])
                print("\n--- Plugin " + plugin + " Output ---\n")
                print(row[2])
                print("--- End plugin Output ---")
    except Error as e:
        print(e)


@click.command(help="Find Containers, Web Apps, Credential failures, Ghost Assets")
@click.option('--plugin', default='', help='Find Assets where this plugin fired')
@click.option('-docker', is_flag=True, help="Find Running Docker Containers")
@click.option('-webapp', is_flag=True, help="Find Web Servers running")
@click.option('-creds', is_flag=True, help="Find Credential failures")
@click.option('--scantime', default='', help='Find Assets where the scan duration is over X mins')
@click.option('-ghost', is_flag=True, help='Find Assets that were discovered by a AWS Connector but not scanned')
@click.option('--port', default='', help='Find assets with a open port provided')
@click.option('--query', default='', help='Query the db directly and display the output')
@click.option('--output', default='', help='Find Assets based on the text in the output. Requires --plugin"')
@click.option('--name', default='', help="Find Assets based on Text in a plugin Name")
def find(plugin, docker, webapp, creds, scantime, ghost, port, query, output, name):

    if output != '' and plugin == '':
        print("You must supply a plugin")
        exit()

    if plugin != '':
        if not str.isdigit(plugin):
            print("You didn't enter a number")
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
                        plugin_cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id='" + plugin + "' and output LIKE '%" + output + "%';")
                    else:
                        find_by_plugin(plugin)

                    plugin_data = plugin_cur.fetchall()
                    for x in plugin_data:
                        print(x[0])
                        print('*' * 20)
                        print(x[2])
                        print('*' * 150)
                        print('*' * 150)
            except Error:
                pass

    if docker:
        print("Searching for RUNNING docker containers...")
        find_by_plugin(str(93561))

    if webapp:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='1442';")

            data = cur.fetchall()
            print("\nWeb Servers found by plugin 1442")
            print("-------------------------------")
            for plugins in data:
                web = plugins[6]  # output
                wsplit = web.split("\n")

                server = wsplit[1]
                web_port = plugins[10]  # port number
                proto = plugins[11]  # Protocol
                asset = plugins[1]  # Ip address
                print()
                print(server, "is running on: ", web_port, "/", proto, "On :", asset)
        try:
            print("\n\nWeb Servers/SSH Servers found by plugin '22964';")
            print("-------------------------------\n")
            conn2 = new_db_connection(database)
            with conn2:
                cur2 = conn.cursor()
                cur2.execute("SELECT output, port, asset_ip from vulns where plugin_id='22964'")
                data = cur2.fetchall()

                for plugins in data:
                    print("\n", plugins[0][:-1], plugins[1], "On :", plugins[2])
                print()
        except IndexError:
            print("No information for plugin 22964")

    if creds:
        print("I'm looking for credential issues...Please hang tight")
        find_by_plugin(str(104410))

    if scantime != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            print("\n*** Below are the assets that took longer than " + str(scantime) + " minutes to scan ***")
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='19506';")

            data = cur.fetchall()
            try:
                print("\nAsset IP".ljust(16), "Asset UUID".ljust(40), "Started".ljust(25), "Finished".ljust(25), "Scan UUID")
                print("-" * 150)
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
                    if minutes > int(scantime):
                        try:
                            print(str(vulns[1]).ljust(15), str(vulns[2]).ljust(40), str(vulns[14]).ljust(25), str(vulns[13]).ljust(25), str(vulns[15]))
                        except ValueError:
                            pass
                print()
            except ValueError:
                pass

    if ghost:
        try:

            ghost_query = {"date_range": "30", "filter.0.filter": "sources", "filter.0.quality": "set-hasonly", "filter.0.value": "AWS"}
            data = request_data('GET', '/workbenches/assets', params=ghost_query)
            print("\nSource".ljust(11), "IP".ljust(15), "FQDN".ljust(45), "First seen")
            print("-" * 150)
            for assets in data['assets']:
                for source in assets['sources']:
                    if source['name'] == 'AWS':
                        aws_ip = assets['ipv4'][0]
                        try:
                            aws_fqdn = assets['fqdn'][0]
                        except IndexError:
                            aws_fqdn = assets['fqdn'][0]

                        print(str(source['name']).ljust(10), str(aws_ip).ljust(15), str(aws_fqdn).ljust(45), source['first_seen'])
            print()

            gcp_query = {"date_range": "30", "filter.0.filter": "sources", "filter.0.quality": "set-hasonly", "filter.0.value": "GCP"}
            gcp_data = request_data('GET', '/workbenches/assets', params=gcp_query)
            for gcp_assets in gcp_data['assets']:
                for gcp_source in gcp_assets['sources']:
                    if gcp_source['name'] == 'GCP':
                        gcp_ip = gcp_assets['ipv4'][0]
                        try:
                            gcp_fqdn = gcp_assets['fqdn'][0]
                        except IndexError:
                            gcp_fqdn = "NO FQDN FOUND"
                            
                        print(gcp_source['name'].ljust(10), gcp_ip.ljust(15), gcp_fqdn.ljust(45), gcp_source['first_seen'])
            print()

            az_query = {"date_range": "30", "filter.0.filter": "sources", "filter.0.quality": "set-hasonly", "filter.0.value": "AZURE"}
            az_data = request_data('GET', '/workbenches/assets', params=az_query)
            for az_assets in az_data['assets']:
                for az_source in az_assets['sources']:
                    if az_source['name'] == 'AZURE':

                        az_ip = az_assets['ipv4'][0]
                        try:
                            az_fqdn = az_assets['fqdn'][0]
                        except IndexError:
                            az_fqdn = "NO FQDN Found"

                        print(az_source['name'].ljust(10), az_ip.ljust(15), az_fqdn.ljust(45), az_source['first_seen'])
            print()
                
        except Exception as E:
            print("Check your API keys or your internet connection")
            print(E)

    if port != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where port=" + port + " and (plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

            data = cur.fetchall()

            try:
                print("\nThe Following assets had Open ports found by various plugins")
                print("\nIP address".ljust(20), " UUID".ljust(45), " Plugins")
                print("-" * 80)
                for vulns in data:
                    print(vulns[1].ljust(20), str(vulns[2]).ljust(45), vulns[7])
            except ValueError:
                pass

    if query != '':
        database = r"navi.db"
        query_conn = new_db_connection(database)
        with query_conn:

            cur = query_conn.cursor()
            cur.execute(query)

            data = cur.fetchall()
            pprint.pprint(data)

    if name != '':
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT asset_ip, asset_uuid, plugin_name, plugin_id from vulns where plugin_name LIKE '%" + name + "%';")

                plugin_data = cur.fetchall()
                print("\nThe Following assets had '{}' in the Plugin Name".format(name))
                print("\nIP address".ljust(20), " UUID".ljust(45), " Plugin Name".ljust(65), " Plugin ID")
                print("-" * 150)
                for vulns in plugin_data:
                    print(vulns[0].ljust(20), str(vulns[1]).ljust(45), textwrap.shorten(str(vulns[2]), 65).ljust(65), vulns[3])
                print()
        except Error:
            pass
