import csv
from sqlite3 import Error
from .database import new_db_connection


def licensed_export():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        with open('licensed_data.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
            header_list = ["IP Address", "FQDN", "UUID", "Last Licensed Scan Date"]
            agent_writer.writerow(header_list)

            cur = conn.cursor()
            try:
                cur.execute("SELECT ip_address, fqdn, uuid, last_licensed_scan_date from assets where last_licensed_scan_date != ' ';")
            except Error:
                print("\n No data! \n Please run 'navi update' first.\n")
            data = cur.fetchall()

            for asset in data:
                agent_writer.writerow(asset)
