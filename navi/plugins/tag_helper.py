import click
from .api_wrapper import request_data
from .database import new_db_connection


def update_tag(c, v, tag_list):
    click.echo("Your tag is being updated\n")
    tag_data = request_data('GET', '/tags/values')
    try:
        for tag in tag_data['values']:
            if tag['category_name'] == str(c):
                if tag['value'] == str(v):
                    try:
                        tag_uuid = tag['uuid']
                        payload = {"action": "add", "assets": tag_list, "tags": [tag_uuid]}
                        data = request_data('POST', '/tags/assets/assignments', payload=payload)
                        click.echo("Job UUID : {}".format(data['job_uuid']))
                    except:
                        pass
    except:
        pass


def tag_checker(uuid, key, value):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        # This needs to be changed to UUID when the api gets fixed
        cur.execute("SELECT * from tags where asset_ip='" + uuid + "' and tag_key='" + key + "' and tag_value='" + value + "';")

        rows = cur.fetchall()

        length = len(rows)
        if length != 0:
            return 'yes'
        return 'no'


def confirm_tag_exists(key, value):
    tag_value_data = request_data('GET', '/tags/values')
    try:
        for tag in tag_value_data['values']:
            if str(tag['category_name']).lower() == str(key).lower():
                if str(tag['value']).lower() == str(value).lower():
                    return 'yes'
    except Exception as E:
        click.echo(E)


def return_tag_uuid(key, value):
    tag_value_data = request_data('GET', '/tags/values')
    try:
        for tag in tag_value_data['values']:
            if str(tag['category_name']).lower() == str(key).lower():
                if str(tag['value']).lower() == str(value).lower():
                    return str(tag['uuid'])
                else:
                    return 'none'
    except Exception as E:
        click.echo(E)


def tag_msg():
    click.echo("Remember to run the update command if you want to use your new tag in navi")
