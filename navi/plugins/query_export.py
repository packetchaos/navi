import csv
import click
from .database import new_db_connection


def query_export(query):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute(query)

        data = cur.fetchall()

        click.echo("I'm exporting query_export.py with your requested data")
        # Crete a csv file object
        with open('query_data.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            # Loop through each asset
            for assets in data:
                agent_writer.writerow(assets)

