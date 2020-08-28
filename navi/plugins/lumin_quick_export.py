import csv
from .database import new_db_connection
from .api_wrapper import tenb_connection

tio = tenb_connection()


def lumin_quick_export():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:

        # Create our headers - We will Add these two our list in order
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Agent-UUID", "last Licensed Scan Date", 'Network ID', 'ACR', 'Asset Exposure Score']

        cur = conn.cursor()
        cur.execute("SELECT * from assets;")

        data = cur.fetchall()

        # Crete a csv file object
        with open('asset_lumin_quick.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            # write our Header information first
            agent_writer.writerow(header_list)

            # Loop through each asset
            for assets in data:
                export_list = []
                for atr in assets:
                    # Cycle through the Database and populate the new list
                    export_list.append(atr)

                # write to the CSV
                agent_writer.writerow(export_list)
