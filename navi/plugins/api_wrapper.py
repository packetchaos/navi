import requests
import click
from sqlite3 import Error
from json import JSONDecodeError
from .database import new_db_connection
from tenable.io import TenableIO


def navi_version():
    return "navi-6.9.0"


def tenb_connection():
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from keys;")
            rows = cur.fetchall()
            for row in rows:
                access_key = row[0]
                secret_key = row[1]
            tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build=navi_version())
            return tio
    except Error:
        pass


def grab_url():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from url;")
            rows = cur.fetchall()
            url = rows[0][1]
        except Error:
            url = 'https://cloud.tenable.com'
    return url


def grab_headers():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from keys;")
        except Error:
            click.echo("\nYou don't have any API keys!  Please enter your keys\n")
            exit()
        rows = cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]
    return {'Content-type': 'application/json', 'user-agent': navi_version(), 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_no_response(method, url_mod, **kwargs):

    # set the Base URL
    url = grab_url() #"https://cloud.tenable.com"

    # check for params and set to None if not found
    try:
        params = kwargs['params']
    except KeyError:
        params = None

    # check for a payload and set to None if not found
    try:
        payload = kwargs['payload']
    except KeyError:
        payload = None

    try:
        r = requests.request(method, url + url_mod, headers=grab_headers(), params=params, json=payload, verify=True)
        if r.status_code == 200:
            click.echo("Success!\n")
        elif r.status_code == 404:
            click.echo('\nCheck your query...{}'.format(r))
        elif r.status_code == 429:
            click.echo("\nToo many requests at a time...\n {}".format(r))
        elif r.status_code == 400:
            click.echo("\nCheck your params.  Password complexity is the most common issue\n{}".format(r))
            click.echo()
        else:
            click.echo("Something went wrong...Don't be trying to hack me now {}".format(r))
    except ConnectionError:
        click.echo("Check your connection...You got a connection error")


def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = grab_url() #"https://cloud.tenable.com"

    # check for params and set to None if not found
    try:
        params = kwargs['params']
    except KeyError:
        params = None

    # check for a payload and set to None if not found
    try:
        payload = kwargs['payload']
    except KeyError:
        payload = None

    # Retry the download three times
    for x in range(1, 3):
        try:
            r = requests.request(method, url + url_mod, headers=grab_headers(), params=params, json=payload, verify=True)
            if r.status_code == 200:
                return r.json()

            if r.status_code == 202:
                # This response is for some successful posts.
                click.echo("\nSuccess!\n")
                break
            elif r.status_code == 404:
                click.echo('\nCheck your query...I can\'t find what you\'re looking for {}'.format(r))
                return r.json()
            elif r.status_code == 429:
                click.echo("\nToo many requests at a time...\n{}".format(r))
                break
            elif r.status_code == 400:
                click.echo("\nThe object you tried to create may already exist\n")
                click.echo("If you are changing scan ownership, there is a bug where 'empty' scans won't be moved")
                break
            elif r.status_code == 403:
                click.echo("\nYou are not authorized! You need to be an admin\n{}".format(r))
                break
            elif r.status_code == 409:
                click.echo("API Returned 409\n If you are changing permissions, it could indicate a duplicate request\n")
                break
            elif r.status_code == 504:
                click.echo("\nOne of the Threads and an issue during download...Retrying...\n{}".format(r))
                break
            else:
                click.echo("Something went wrong...Don't be trying to hack me now {}".format(r))
                click.echo(r.request)
                click.echo(r.headers)
                click.echo(r.reason)
                break
        except ConnectionError:
            click.echo("Check your connection...You got a connection error. Retying")
            continue
        except JSONDecodeError:
            click.echo("Download Error or User enabled / Disabled ")
            continue
