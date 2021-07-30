import csv
import click
from sqlite3 import Error
from .database import new_db_connection


def query_export(query, name):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute(query)
        except Error:
            print("\n No data! \n Please run 'navi update' first. OR check your query.\n")

        data = cur.fetchall()
        descripts = cur.description
        header = []

        for desc in descripts:
            header.append(desc[0])

        click.echo("I'm exporting {}.csv with your requested data".format(name))

        # Crete a csv file object

        with open('{}.csv'.format(name), mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
            agent_writer.writerow(header)
            # Loop through each asset
            for assets in data:
                agent_writer.writerow(assets)

