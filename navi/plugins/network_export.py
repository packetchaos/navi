import csv
from .database import new_db_connection


def network_export(network):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:

        # Create our headers - We will Add these two our list in order
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Agent-UUID", "last Licensed Scan Date", "Network ID"]
        cur = conn.cursor()
        cur.execute("SELECT * from assets where network=='" + network + "';")

        data = cur.fetchall()

        # Crete a csv file object
        with open('network_data.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            # write our Header information first
            agent_writer.writerow(header_list)

            # Loop through each asset
            for assets in data:
                agent_writer.writerow(assets)
