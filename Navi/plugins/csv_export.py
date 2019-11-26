import csv
from .database import new_db_connection

def csv_export():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:

        #Create our headers - We will Add these two our list in order
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Tags", "Info", "Low", "Medium", "High", "Critical"]
        cur = conn.cursor()
        cur.execute("SELECT * from assets;")

        data = cur.fetchall()

        #Crete a csv file object
        with open('asset_data_new.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            #write our Header information first
            agent_writer.writerow(header_list)

            #Loop through each asset
            for assets in data:

                agent_writer.writerow(assets)
