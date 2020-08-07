import requests
from json import JSONDecodeError
from .database import new_db_connection


def grab_headers():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * from keys;")
        rows = cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]
    return {'Content-type': 'application/json', 'user-agent': 'navi-5.2.2', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_delete(method, url_mod):

    # set the Base URL
    url = "https://cloud.tenable.com"

    try:
        r = requests.request(method, url + url_mod, headers=grab_headers(), verify=True)
        if r.status_code == 200:
            print("Success!\n")
        elif r.status_code == 404:
            print('\nCheck your query...', r)
        elif r.status_code == 429:
            print("\nToo many requests at a time...\n", r)
        else:
            print("Something went wrong...Don't be trying to hack me now", r)
    except ConnectionError:
        print("Check your connection...You got a connection error")


def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = "https://cloud.tenable.com"

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
                print("\nSuccess!\n")
                break
            elif r.status_code == 404:
                print('\nCheck your query...I can\'t find what you\'re looking for', r)
                return r.json()
            elif r.status_code == 429:
                print("\nToo many requests at a time...\n", r)
                break
            elif r.status_code == 400:
                print("\nThe object you tried to create may already exist\n")
                print("If you are changing scan ownership, there is a bug where 'empty' scans won't be moved")
                break
            elif r.status_code == 403:
                print("\nYou are not authorized! You need to be an admin\n", r)
                break
            elif r.status_code == 409:
                print("\nScan is not Active\n", r)
                break
            elif r.status_code == 504:
                print("\nOne of the Threads and an issue during download...Retrying...\n", r)
                break
            else:
                print("Something went wrong...Don't be trying to hack me now", r)
                break
        except ConnectionError:
            print("Check your connection...You got a connection error. Retying")
            continue
        except JSONDecodeError:
            print("Download Error. Retrying")
            continue
