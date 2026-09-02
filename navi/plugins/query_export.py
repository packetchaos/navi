import csv
import click
from sqlite3 import Error
from .database import new_db_connection, regexp
from .export_utils import csv_path


def query_export(query, name):
    """Write the results of `query` to <name>.csv and return the resolved path.

    `name` may be supplied with or without the '.csv' extension.
    """
    database = r"navi.db"
    path = csv_path(name)
    conn = new_db_connection(database)
    with conn:
        conn.create_function("REGEXP", 2, regexp)
        cur = conn.cursor()
        try:
            cur.execute(query)
        except Error:
            print("\n No data! \n Please run 'navi update' first. OR check your query.\n")
            return None

        # Grab the Data
        data = cur.fetchall()

        # Grab the Table data
        descripts = cur.description

        # Create Header list
        header = []

        # Pull the row data out to populate the headers
        for desc in descripts:
            header.append(desc[0])

        # Create a csv file object
        with open(path, mode='w', encoding='utf-8', newline="") as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
            agent_writer.writerow(header)
            # Loop through each asset
            for assets in data:
                agent_writer.writerow(assets)

    click.echo("\nWrote {} - {} rows\n".format(path, len(data)))
    return path
