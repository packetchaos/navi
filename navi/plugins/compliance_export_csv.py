import csv
import click
from sqlite3 import Error
from .database import new_db_connection


def compliance_export_csv():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from compliance;")
        except Error:
            print("\n No data! \n Please run 'navi update compliance' first\n")

        data = cur.fetchall()

        click.echo("I'm exporting compliance_data.csv with your requested data")

        header_list = ["asset_uuid", "actual_value", "audit_file", "check_id", "check_info", "check_name",
                       "expected_value", "first_seen", "last_seen", "plugin_id", "reference", "see_also", "solution",
                       "status"]

        # Crete a csv file object
        with open('compliance_data.csv', mode='w') as csv_file:
            compliance_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            compliance_writer.writerow(header_list)
            # Loop through each asset
            for assets in data:
                compliance_writer.writerow(assets)

