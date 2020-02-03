import click
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection


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
@click.option('--time', default='', help='Find Assets where the scan duration is over X mins')
@click.option('-ghost', is_flag=True, help='Find Assets that were discovered by a AWS Connector but not scanned')
@click.option('--port', default='', help='Find assets with an open port')
def find(plugin, docker, webapp, creds, time, ghost, port):

    if plugin != '':
        if not str.isdigit(plugin):
            print("You didn't enter a number")
        else:
            find_by_plugin(plugin)

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

            for plugins in data:
                web = plugins[6]  # output
                wsplit = web.split("\n")

                server = wsplit[1]
                port = plugins[10]  # port number
                proto = plugins[11]  # Protocol
                asset = plugins[1]  # Ip address

                print(asset, ": Has a Web Server Running :")
                print(server, "is running on: ", port, "/", proto)
                print()

    if creds:
        print("I'm looking for credential issues...Please hang tight")
        find_by_plugin(str(104410))

    if time != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            print("Below are the assets that took longer than " + str(time) + " minutes to scan")
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='19506';")

            data = cur.fetchall()
            try:
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
                    if minutes > int(time):
                        try:
                            print("Asset IP: ", vulns[1])
                            print("Asset UUID: ", vulns[2])
                            print("Scan started at: ", vulns[14])
                            print("Scan completed at: ", vulns[13])
                            print("Scan UUID: ", vulns[15])
                            print()
                        except ValueError:
                            pass
            except ValueError:
                pass

    if ghost:
        try:
            query = {"date_range": "30", "filter.0.filter": "sources", "filter.0.quality": "set-hasonly", "filter.0.value": "AWS"}
            data = request_data('GET', '/workbenches/assets', params=query)
            print("\nSource", "IP", "FQDN", "First seen")
            print("----------------------------------\n")
            for assets in data['assets']:

                for source in assets['sources']:
                    if source['name'] == 'AWS':
                        print(source['name'], assets['ipv4'][0], assets['fqdn'][0], source['first_seen'])

            print()
        except:
            print("Check your API keys or your internet connection")

    if port != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where port=" + port + " and (plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

            data = cur.fetchall()

            try:
                print("\nThe Following assets had Open ports found by various plugins")
                print("\nIP address".ljust(15), " UUID".ljust(36), " Plugins")
                print("-------------------------------------------------------------\n")
                for vulns in data:
                    print(vulns[1].ljust(15), vulns[2], vulns[7])
            except ValueError:
                pass
