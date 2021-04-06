import requests
from json import JSONDecodeError


def script_version():
    return "navi - TTL Script - 0.0.2"


def grab_headers():

    access_key = "Access Key"
    secret_key = "Secret Key"

    return {'Content-type': 'application/json', 'user-agent': script_version(), 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


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
                print('\nCheck your query...I can\'t find what you\'re looking for {}'.format(r))
                return r.json()
            elif r.status_code == 429:
                print("\nToo many requests at a time...\n{}".format(r))
                break
            elif r.status_code == 400:
                print("\nThe object you tried to create may already exist\n")
                print("If you are changing scan ownership, there is a bug where 'empty' scans won't be moved")
                break
            elif r.status_code == 403:
                print("\nYou are not authorized! You need to be an admin\n{}".format(r))
                break
            elif r.status_code == 409:
                print("API Returned 409")
                break
            elif r.status_code == 504:
                print("\nOne of the Threads and an issue during download...Retrying...\n{}".format(r))
                break
            else:
                print("Something went wrong...Don't be trying to hack me now {}".format(r))
                break
        except ConnectionError:
            print("Check your connection...You got a connection error. Retying")
            continue
        except JSONDecodeError:
            print("Download Error or User enabled / Disabled ")
            continue


def change_ttl(age, net):
    print("\nChanging the age to {}\n".format(age))

    if age != '' and net != '' and len(net) == 36:
        if 1 <= int(age) <= 365:
            network_data = request_data('GET', '/networks/' + net)
            name = network_data['name']
            payload = {"assets_ttl_days": age, "name": name, "description": "TTL adjusted by TTL Script"}
            request_data('PUT', '/networks/' + net, payload=payload)
        else:
            print("Asset Age Out number must between 1 and 365")
    else:
        print("Please enter a Age value and a network UUID")


def change_ttl_for_all_networks():
    # Enumerate all Network IDs
    params = {"limit": "500"}
    data = request_data('GET', '/networks', params=params)

    network_list = []
    for network in data['networks']:
        uuid = network['uuid']
        print(uuid, network['assets_ttl_days'])
        #change_ttl(age=30, net=uuid)


change_ttl_for_all_networks()
