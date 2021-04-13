import click
from .database import new_db_connection
from .tag_helper import tag_checker
from .api_wrapper import request_data


@click.command(help="Adjust ACRs in Lumin by tag")
@click.option('--acr', default='', help='Set the ACR')
@click.option('--c', default='', help="Category to use")
@click.option('--v', default='', help="Value to use")
@click.option('--note', default="navi Generated", help="Enter a Note to your ACR Rule")
@click.option('-business', '-b', is_flag=True, help="Add Business Critical To ACR Change Reason(s)")
@click.option('-compliance', '-c', is_flag=True, help="Add Compliance To ACR Change Reason(s)")
@click.option('-mitigation', '-m', is_flag=True, help="Add Mitigation Controls To ACR Change Reason(s)")
@click.option('-development', '-d', is_flag=True, help="Add Development To ACR Change Reason(s)")
def lumin(acr, v, c, note, business,  compliance, mitigation, development):
    choice = []
    if c == '':
        click.echo("We require a Tag Category to update the ACR by Tag")
        exit()

    if v == '':
        click.echo("We require a Tag value to update the ACR by Tag")
        exit()

    if business:
        choice.append("Business Critical")

    if compliance:
        choice.append("In Scope For Compliance")

    if mitigation:
        choice.append("Existing Mitigation Control")

    if development:
        choice.append("Dev Only")

    if not business and not mitigation and not compliance and not development:
        choice.append("Key Drivers does not match")

    if note != 'navi Generated':
        choice.append("Other")

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

            if not lumin_list:
                click.echo("We did not find a Tag with that Category or Value... "
                           "It's also possible the tag has not been applied to any assets\n")
                click.echo("If you think this is an error, surround your category and value in \"\"")
                exit()
            else:
                note = note + " - navi"
                # this needs to be changed to ID once the api is fixed
                lumin_payload = [{"acr_score": int(acr), "reason": choice, "note": note, "asset": [{"ipv4": lumin_list}]}]
                request_data('POST', '/api/v2/assets/bulk-jobs/acr', payload=lumin_payload)

    else:
        click.echo("You can't have a score below 1 or higher than 10")
