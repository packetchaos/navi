import requests
import click
import gzip
import shutil
import csv
from .dbconfig import create_epss_table, new_db_connection, create_zipper_table
from .database import insert_epss, drop_tables, db_query, insert_zipper


def zipper_epss_plugin():
    database = r"navi.db"
    zipper_conn = new_db_connection(database)
    drop_tables(zipper_conn, 'zipper')
    create_zipper_table()

    plugin_list = db_query("select plugin_id, cves, vpr_score from plugins where severity != 'info';")
    with zipper_conn:
        for plugin in plugin_list:
            plugin_zipper_list = []
            highest_cve = 0
            plugin_zipper_list.append(plugin[0])
            try:
                for cve in (eval(plugin[1])):
                    score = db_query("select epss_value from epss where cve='{}'".format(str(cve)))
                    if float(score[0][0]) >= highest_cve:
                        highest_cve = float(score[0][0])
                    else:
                        pass
                plugin_zipper_list.append(highest_cve)
            except SyntaxError:
                plugin_zipper_list.append("NO CVE")
            except IndexError:
                plugin_zipper_list.append("NO CVE")

            insert_zipper(zipper_conn, plugin_zipper_list)


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


def update_navi_with_epss(day, month, year, filename):
    click.echo("\nParsing the csv and importing values into the table epss\n")
    try:
        if filename:
            epss_csv_file = filename
        else:
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

        click.echo("\nNow we are zippering Plugin data with EPSS in a table called zipper\n Use this for exports\n")
        zipper_epss_plugin()
    except Exception as E:
        click.echo(E)
        click.echo("\nBe sure you are using YYYY, MM, and DD values and not single digit values.\n")
