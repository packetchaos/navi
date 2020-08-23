import csv
import click
from .database import new_db_connection
from .api_wrapper import tenb_connection

tio = tenb_connection()


def lumin_export():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:

        # Create our headers - We will Add these two our list in order
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Agent-UUID", "last Licensed Scan Date", 'Network ID', 'Info', 'Low', 'Medium',
                       'High', 'Critical', 'Asset Exposure Score',' ACR', 'ACR Driver Name', "ACR Driver Value",
                       "ACR Driver Name", "ACR Driver Value", "ACR Driver Name", "ACR Driver Value"]

        cur = conn.cursor()
        cur.execute("SELECT * from assets;")

        data = cur.fetchall()

        # Crete a csv file object
        with open('asset_lumin.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            # write our Header information first
            agent_writer.writerow(header_list)

            # Loop through each asset
            for assets in data:
                export_list = []
                for atr in assets:
                    # Cycle through the Database and populate the new list
                    export_list.append(atr)

                asset_id = assets[3]  # Grab the UUID to make API calls
                try:
                    asset_info = tio.workbenches.asset_info(asset_id)

                    for vuln in asset_info['counts']['vulnerabilities']['severities']:
                        export_list.append(vuln["count"])  # Add the vuln counts to the new list

                    try:
                        export_list.append(asset_info['exposure_score'])  # add the exposure score
                        export_list.append(asset_info['acr_score'])  # add the ACR
                    except KeyError:
                        pass

                    for driver in range(3):
                        try:
                            export_list.append(asset_info['acr_drivers'][driver]['driver_name'])  # add the ACR drivers
                        except:
                            export_list.append(" ")

                        try:
                            export_list.append(asset_info['acr_drivers'][driver]['driver_value'][0])
                        except:
                            export_list.append(" ")

                except ConnectionError:
                    click.echo("Check your API keys or your internet connection")
                # write to the CSV
                agent_writer.writerow(export_list)
