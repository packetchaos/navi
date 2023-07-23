import requests
import click
import gzip
import shutil
import csv
from .dbconfig import create_epss_table, new_db_connection
from .database import insert_epss, drop_tables


def request_new_data(day, month, year):
    epss_data_name = "epss_scores-{}-{}-{}.csv".format(year, month, day)
    # URL structure https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz
    epss_url = "https://epss.cyentia.com/epss_scores-{}-{}-{}.csv.gz".format(year, month, day)

    epss_data = requests.request('GET', epss_url)

    click.echo("\nDownloading {} from {}\n".format(epss_data_name, epss_url))
    with open("{}.gz".format(epss_data_name), 'wb') as zfile:
        zfile.write(epss_data.content)

    click.echo("\nUnzipping the file now\n")
    with gzip.open("{}.gz".format(epss_data_name), 'rb') as zip_ref:
        with open("{}".format(epss_data_name), 'wb') as csv_ref:
            shutil.copyfileobj(zip_ref, csv_ref)

    return epss_data_name


def update_navi_with_epss(day, month, year):
    click.echo("\nParsing the csv and importing values into the table epss\n")
    try:
        epss_csv_file = request_new_data(day, month, year)
        database = r"navi.db"
        epss_conn = new_db_connection(database)
        drop_tables(epss_conn, 'epss')
        create_epss_table()

        with open(epss_csv_file, 'r') as epss_csv:
            reader = csv.reader(epss_csv)
            header_one = next(reader)
            header_two = next(reader)
            with epss_conn:

                for row in reader:
                    new_list = [str(row[0]), str(row[1]), str(row[2])]
                    insert_epss(epss_conn, new_list)
    except Exception as E:
        click.echo(E)
        click.echo("\nBe sure you are using YYYY, MM, and DD values and not single digit values.\n")




