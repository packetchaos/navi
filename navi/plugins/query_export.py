import csv
import click
from sqlite3 import Error
from .database import new_db_connection


def query_export(query):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute(query)
        except Error:
            print("\n No data! \n Please run 'navi update' first. OR check your query.\n")

        data = cur.fetchall()

        click.echo("I'm exporting query_data.csv with your requested data")
        # Crete a csv file object
        with open('query_data.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            # Loop through each asset
            for assets in data:
                agent_writer.writerow(assets)

