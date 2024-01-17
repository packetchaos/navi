from os import system as sys
import json
import time
import subprocess

# Instructions #
# Replace 'access_key and secret_key with your keys
# Add/remove or adjust any of the below commands
# The structure is there to help you with the command syntax.

start = time.time()



def seed_container():
    sys("echo Uploading Seeded Nessus Scan")
    sys('navi scan upload \"Daily_Scan_Production_Network.nessus\"')

    sys("echo Uploading Seeded WAS Scan")
    sys("navi was upload \"WAS.json\"")

    # Need to check for 30 assets
    ready = False

    while ready is False:
        asset_request = subprocess.check_output('navi api \"/workbenches/assets?date_range=7\"', shell=True)
        asset_json = asset_request.decode('utf-8')
        asset_count = eval(asset_json)['total']

        if asset_count > 30:
            ready = True
        print("confirm looping")
        # Check every 5 mins
        time.sleep(300)


def decorate_container():
    sys("echo Creating users and groups\n Adding users to appropriate Groups")

    # Create Users and Groups
    sys('navi automate --sheet users')

    # Create FQDN Tags
    sys('navi automate --sheet tags_fqdn')

    # Create Advanced tags
    sys('navi automate --sheet advanced_tags')
    time.sleep(120)

    # Create permissions based on Tags
    sys('navi automate --sheet permissions')


def delete_all_users():
    navi_request = subprocess.check_output('navi api \"/users\"', shell=True)
    navi_json = navi_request.decode('utf-8')

    for users in eval(navi_json)['users']:
        if not users['undeletable']:
            sys('navi delete user {}'.format(users['id']))


def delete_all_groups():
    navi_request = subprocess.check_output('navi api \"/groups\"', shell=True)
    navi_json = navi_request.decode('utf-8')

    for groups in eval(navi_json)['groups']:
        if str(groups['id']) != '0':
            sys('navi delete usergroup {}'.format(groups['id']))


def delete_all_tags():
    navi_request = subprocess.check_output('navi api \"/tags/categories\"', shell=True)
    navi_json = navi_request.decode('utf-8')

    for tags in eval(navi_json)['categories']:
            sys('navi delete category {}'.format(tags['uuid']))


# Decorate the container
decorate_container()

# Clean up the container
#delete_all_tags()
#delete_all_users()
#delete_all_groups()