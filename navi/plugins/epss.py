import requests
import click
import csv
from .dbconfig import create_epss_table, new_db_connection
from .database import insert_epss, drop_tables

epss_data_name = 'epss_scores-2023-01-07.csv'


def request_new_data(day, month, year, file):
    # URL structure https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz
    epss_url = "https://epss.cyentia.com/epss_scores-{}-{}-{}.csv.gz".format(year, month, day)

    epss_data = requests.request('GET', epss_url)

    with open(epss_data_name, 'wb') as zfile:
        zfile.write(epss_data.content)

    # Need code to unzip gzip


def update_navi_with_epss(day, month, year, file):
    click.echo("Not yet ready.  Releasing in a few weeks!")
    '''
    #request_new_data(day, month, year, file)
    # Open the file
    # Write each CVSS Data in each folder to a db
    database = r"navi.db"
    epss_conn = new_db_connection(database)
    drop_tables(epss_conn, 'epss')
    create_epss_table()

    with open(epss_data_name, 'r') as epss_csv:
        reader = csv.reader(epss_csv)
        header_one = next(reader)
        header_two = next(reader)
        with epss_conn:

            for row in reader:
                new_list = [str(row[0]), str(row[1]), str(row[2])]
                insert_epss(epss_conn, new_list)
    '''

