import csv
import click
from sqlite3 import Error
from .database import new_db_connection, regexp
from .export_utils import csv_path


def export_query(query, name):
    """Same as query_export(), but spills any cell over 32K chars to a sidecar.

    Returns the resolved CSV path.  `name` may be supplied with or without the
    '.csv' extension.
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
            number = 0
            for assets in data:
                # Create a new list to pump new data in:
                new_list = []
                for deets in list(assets):
                    # Check for length
                    if len(str(deets)) > 31999:
                        number += 1

                        with open("extra_data_{}.txt".format(number), mode='w', encoding='utf-8') as text_file:
                            text_file.writelines(deets)
                        new_list.append("The text was over 32K Chars and was moved to the "
                                        "file: extra_data_{}.txt".format(number))
                    else:
                        new_list.append(deets)

                agent_writer.writerow(new_list)

    click.echo("\nWrote {} - {} rows\n".format(path, len(data)))
    if number != 0:
        click.echo("{} records were over 32K chars; each was saved to its own "
                   "extra_data_<n>.txt and referenced in the CSV\n".format(number))
    return path
