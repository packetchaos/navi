import click
from .api_wrapper import request_data
from .database import new_db_connection


def grab_all_tags():
    # Quick solution to get to 10,000 Tag limit.
    # next itration will be to clean this up and remove any limits

    querystring = {'limit': 5000}
    tag_value_data = request_data('GET', '/tags/values', params=querystring)
    total_tags = tag_value_data['pagination']['total']

    tag_list = []

    for tag in tag_value_data['values']:
        my_tuple = (tag['category_name'], tag['value'], tag['uuid'])
        tag_list.append(my_tuple)

    if total_tags > 5000:
        querystring = {'offset': 5000}
        new_tags = request_data('GET', '/tags/values', params=querystring)

        for tags in new_tags['values']:
            my_tuples = (tags['category_name'], tags['value'], tags['uuid'])
            tag_list.append(my_tuples)

    return tag_list


def update_tag(c, v, tag_list):
    click.echo("Your tag is being updated\n")

    try:
        list_tags = grab_all_tags()

        for tag_info in list_tags:
            if str(tag_info[0]).lower() == str(c).lower():
                if str(tag_info[1]).lower() == str(v).lower():

                    try:
                        tag_uuid = tag_info[2]
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
    try:
        tag_list = grab_all_tags()

        for tag_info in tag_list:
            if str(tag_info[0]).lower() == str(key).lower():
                if str(tag_info[1]).lower() == str(value).lower():
                    return 'yes'
    except Exception as E:
        click.echo(E)


def return_tag_uuid(key, value):
    # Helper function for Tag by group
    querystring = {'limit': 5000}
    tag_value_data = request_data('GET', '/tags/values', params=querystring)
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
