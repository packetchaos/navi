import csv
import click
from sqlite3 import Error
from .database import new_db_connection


def compliance_export_csv(name, uuid, file_name):

    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        # Since the Compliance export doesn't have the FQDN of the asset, pull it from the asset table
        try:
            if name and uuid:
                cur.execute("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                            "assets.uuid = compliance.asset_uuid "
                            "where compliance.audit_file='{}' and compliance.asset_uuid='{}';".format(name, uuid))
            elif name:
                cur.execute("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                            "assets.uuid = compliance.asset_uuid "
                            "where audit_file='{}';".format(name))

                file_name = "{}.csv".format(name)
            elif uuid:
                cur.execute("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                            "assets.uuid = compliance.asset_uuid "
                            "where asset_uuid='{}';".format(uuid))

                file_name = "{}.csv".format(uuid)
            else:
                cur.execute("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                            "assets.uuid = compliance.asset_uuid;")
        except Error:
            print("\n No data! \n Please run 'navi update compliance' first\n")

        data = cur.fetchall()

        click.echo("I'm exporting {} with your requested data\n".format(file_name))

        header_list = ["FQDN", "asset_uuid", "actual_value", "audit_file", "check_id", "check_info", "check_name",
                       "expected_value", "first_seen", "last_seen", "plugin_id", "reference", "see_also", "solution",
                       "status"]

        # Crete a csv file object
        with open(file_name, mode='w', encoding='utf-8') as csv_file:
            compliance_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            compliance_writer.writerow(header_list)
            # Loop through each asset
            for assets in data:
                compliance_writer.writerow(assets)
