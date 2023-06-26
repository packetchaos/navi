import csv
import click
from sqlite3 import Error
from .database import new_db_connection
from os import system as cmd


def export_query(query, name):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute(query)
        except Error:
            print("\n No data! \n Please run 'navi update' first. OR check your query.\n")

        # Grab the Data
        data = cur.fetchall()

        # Grab the Table data
        descripts = cur.description

        # Create Header list
        header = []

        # Pull the row data out to populate the headers
        for desc in descripts:
            header.append(desc[0])

        click.echo("I'm exporting {}.csv with your requested data".format(name))

        # Crete a csv file object

        with open('{}.csv'.format(name), mode='w', encoding='utf-8', newline="") as csv_file:
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
                        new_list.append("The text was over 32K Chars and was moved to the file: extra_data_{}.txt".format(number))
                    else:
                        new_list.append(deets)

                agent_writer.writerow(new_list)

            if number != 0:
                print("\nYou're export had {} records that were over 32K; \nThey were all saved to a text file which is referenced in the CSV\n".format(number))
