import csv
from .api_wrapper import request_data


def user_export():
    user_data = request_data("GET", "/users")

    # for some reason if a name isn't given no key is created.
    header_list = ["Name", "User Name", "UUID", "Roles", "Total Failed Attempts"]
    with open('user_data.csv', mode='w', encoding='utf-8') as csv_file:
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
            roles = user['roles']
            fail = user['login_fail_total']

            user_list.append(name)
            user_list.append(user_name)
            user_list.append(user_uuid)
            user_list.append(roles)
            user_list.append(fail)

            user_writer.writerow(user_list)
