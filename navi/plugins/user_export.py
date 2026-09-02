import csv
from .api_wrapper import request_data
from .export_utils import csv_path


def user_export(name="user_data"):
    user_data = request_data("GET", "/users")

    # for some reason if a name isn't given a key isn't created.
    header_list = ["Name", "User Name", "UUID", "permissions", "Total Failed Attempts"]

    path = csv_path(name)

    with open(path, mode='w', encoding='utf-8', newline="") as csv_file:
        user_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        # write our Header information first
        user_writer.writerow(header_list)

        for user in user_data['users']:
            user_list = []
            try:
                name = user['name']
            except KeyError:
                name = " "

            user_name = user['username']
            user_uuid = user['uuid']
            try:
                roles = user['permissions']
            except KeyError:
                roles = None

            fail = user['login_fail_total']

            user_list.append(name)
            user_list.append(user_name)
            user_list.append(user_uuid)
            user_list.append(roles)
            user_list.append(fail)

            user_writer.writerow(user_list)

    return path
