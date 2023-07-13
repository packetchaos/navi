import requests
import csv
from .dbconfig import create_epss_table, new_db_connection
from .database import insert_epss, drop_tables, db_query

epss_data_name = 'epss_scores-2023-01-07.csv'


def request_new_data():
    # URL structure https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz
    epss_url = 'https://epss.cyentia.com/epss_scores-2023-01-07.csv.gz'


    epss_data = requests.request('GET', epss_url)

    with open(epss_data_name, 'wb') as zfile:
        zfile.write(epss_data.content)

    # Need code to unzip gzip


def update_navi_with_epss():

    # Open the file
    # Write each CVSS Data in each folder to a db
    print("Making DB connection ")
    database = r"navi.db"
    epss_conn = new_db_connection(database)
    print("Dropping table")
    drop_tables(epss_conn, 'score')
    print("creating table")
    create_epss_table()
    new_list = []
    test_list = ('CVE-1999-1593', '0.20648', '0.96362')

    #insert_epss(epss_conn, test_list)

    with open(epss_data_name, 'r') as epss_csv:

        reader = csv.reader(epss_csv)
        header_one = next(reader)
        header_two = next(reader)

        for row in reader:
            statement = "insert into score(cve, epss_value, percentile) values({}, {}, {})".format(row[0], row[1], row[2])
            db_query(statement)


