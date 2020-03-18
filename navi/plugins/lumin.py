import click
from .database import new_db_connection
from .tag_helper import tag_checker
from .api_wrapper import request_data


@click.command(help="Adjust ACRs in Lumin by tag")
@click.option('--acr', default='', help='Set the ACR')
@click.option('--c', default='', help="Category to use")
@click.option('--v', default='', help="Value to use")
@click.option('--note', default="navi Generated", help="Enter a Note to your ACR Rule")
def lumin(acr, v, c, note):
    if c == '':
        print("We require a Tag Category to update the ACR by Tag")
        exit()

    if v == '':
        print("We require a Tag value to update the ACR by Tag")
        exit()

    if int(acr) in range(1, 11):
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            # this needs to be changed to uuid once the api gets fixed
            cur.execute("SELECT asset_ip from tags where tag_key='" + c + "' and tag_value='" + v + "';")

            data = cur.fetchall()

            lumin_list = []
            for asset in data:
                # grab the first record, in this case the uuid
                uuid = asset[0]
                check_for_no = tag_checker(uuid, "NO", "UPDATE")
                if check_for_no == 'no':
                    check_match = tag_checker(uuid, c, v)
                    if check_match == 'yes':
                        lumin_list.append(uuid)
                else:
                    pass

            if lumin_list == []:
                print("We did not find a Tag with that Category or Value\n")
                print("If you think this is an error, surround your category and value in \"\"")
                exit()
            else:
                choice = []
                print("\n1. Business Critical")
                biz = "Business Critical"

                print("2. In Scope For Compliance")
                comp = "In Scope For Compliance"

                print("3. Existing Mitigation Control")
                control = "Existing Mitigation Control"

                print("4. Dev Only")
                dev = "Dev Only"

                print("5. Key Drivers does not match")
                driver = "Key Drivers does not match"

                print("6. other\n")
                other = "Other"

                string_choice = input("Please Choose the Reasons for the Asset criticality.\nSeparate multiple choices by a comma: e.g: 1,2,4\n")

                if "1" in string_choice:
                    choice.append(biz)
                if "2" in string_choice:
                    choice.append(comp)
                if "3" in string_choice:
                    choice.append(control)
                if "4" in string_choice:
                    choice.append(dev)
                if "5" in string_choice:
                    choice.append(driver)
                if "6" in string_choice:
                    choice.append(other)

                note = note + " - navi Generated"
                # this needs to be changed to ID once the api is fixed
                lumin_payload = [{"acr_score": int(acr), "reason": choice, "note": note, "asset": [{"ipv4": lumin_list}]}]
                request_data('POST', '/api/v2/assets/bulk-jobs/acr', payload=lumin_payload)

    else:
        print("You can't have a score below 1 or higher than 10")
