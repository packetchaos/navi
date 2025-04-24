import click
import textwrap
import os
import re
import random
import time
import string
import pandas as pd
import numpy as np
from .database import new_db_connection, db_query
from .api_wrapper import request_data, request_no_response, tenb_connection
from .send_mail import send_attachment
from collections import defaultdict
from typing import Optional, Dict, Tuple
from os import system as cmd
try:
    # this is only needed for an obscure component of navi.  navi push...
    import pexpect
    from pexpect import pxssh
except ImportError:
    # print("\nInformation: Navi push will not work on this system!\n")
    pass


PASSWORD_LENGTH = 20


PROMPT = ['#', '>>> ', '> ', '$ ']

tio = tenb_connection()


@click.group(help="Add Agents to groups, Deploy Navi Services, Mail Commands/files, "
                  "CnC using push, cancel asset/vuln exports and delete tags, users, scans etc")
def action():
    pass


def grab_keys():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from keys;")
        except:
            click.echo("\nYou don't have any API keys!  Please enter your keys\n")
            exit()
        rows = cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]

    return access_key, secret_key


def grab_smtp():
    # grab SMTP information
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * from smtp;")
        rows = cur.fetchall()

        for row in rows:

            server = row[0]
            port = row[1]
            from_email = row[2]
            password = row[3]

        return server, port, from_email, password


def send_command(shell, cmd, quick):
    if quick == 1:
        shell.sendline(cmd)
        shell.expect(PROMPT)
    else:
        shell.sendline(cmd)
        shell.expect(PROMPT, timeout=300)
        shell.expect(pexpect.TIMEOUT)

    response = shell.before
    print()
    print(response.decode('utf-8'))
    print()


def connect(user, host, password, command):
    try:
        if "sudo" in command:
            conn = pxssh.pxssh()
            conn.login(host, user, password)
            conn.sendline(command)
            conn.prompt()
            conn.sendline(password)
            conn.prompt()

            raw = conn.before
            print(raw.decode('utf-8'))
            conn.logout()
        else:
            conn = pxssh.pxssh()
            conn.login(host, user, password)
            conn.sendline(command)
            conn.prompt()
            raw = conn.before
            print(raw.decode('utf-8'))
            conn.logout()
    except pxssh.ExceptionPxssh as e:
        print(e)


def scp(user, host, password, filename):
    ssh_new_key_string = 'Are you sure you want to continue connecting'
    scp_login_string = 'scp {} {}@{}:/'.format(filename, user, host)

    try:
        shell = pexpect.spawn(scp_login_string, timeout=300)

        return_code = shell.expect([pexpect.TIMEOUT, ssh_new_key_string, '[P|p]assword:'])

        if return_code == 0:
            print("error connecting")
            exit()

        if return_code == 1:
            shell.sendline('yes')
            second_return_code = shell.expect([pexpect.TIMEOUT, '[P|p]assword:'])

            if second_return_code == 0:
                print("error connecting")
                return

        shell.sendline(password)
        shell.expect(pexpect.EOF)
        response = shell.before
        print(response.decode('utf-8'))
        print()
    except:
        print("\nThis Feature has been disabled.  You're system doesn't allow for pexpect.spawn\n")


class Excel:
    def __init__(self, file_path: str, sheet_names: Optional[list]=None) -> None:
        self.excel = pd.ExcelFile(file_path)
        self._file_path = file_path
        # include all sheets or just ones that were specified in sheet_names
        if sheet_names is not None:
            self.sheet_names = [name for name in self.excel.sheet_names if name in sheet_names]
        else:
            self.sheet_names = self.excel.sheet_names

        self.sheets = {name: self.parse_sheet(name) for name in self.sheet_names}

    def get_sheet_action(self, sheet_name, action):
        return [record for record in self.records[sheet_name] if record['action'] == 'action']

    def parse_sheet(self, sheet_name: str):
        df = self.excel.parse(sheet_name)
        df = df.applymap(strip_whitespace)
        records = df.replace(np.nan, None).to_dict('records')
        return records

    def get_records(self, action='create', asset_tag_filters=None):
        return post_process_sheets(self.sheets, asset_tag_filters=asset_tag_filters, action=action)


def strip_whitespace(value):
    if isinstance(value, str):
        value = re.sub('\n+', ',', value.strip())
        value = re.sub('[ ]*,[ ]*', ',', value.strip())
    return value


def generate_password(length=PASSWORD_LENGTH):
    special_chars = '~!@#$%^&*()-_+='
    password_chars = string.digits + string.ascii_letters + special_chars
    return "".join(random.choices(password_chars, k=length))


def insert_password(user):
    user['password'] = generate_password()
    return user


def username_to_lower(user):
    user['username'] = user['username'].lower()
    return user


def str_to_api_name(name):
    if name.startswith('tags') or name.endswith('tags'):
        name = 'tags'
    return name


def parse_filter_name(column_name: str, asset_tag_filters: dict) -> Tuple[dict, str]:
    '''split value into (filter_name, operator)

    The filter column name will be either:
        - the name of a filter, i.e. ipv4
        - OR the <name><' ' or '_'><operator

    '''
    # default to equal when the value is a filter_name with out the operator
    operator = 'eq'
    filter_name = column_name

    # get the dictionary of valid filter names and operators
    tag_filter = asset_tag_filters.get(column_name)

    if tag_filter is None:
        # see if there is an operator appended to the filter_name
        match = re.match('(?P<filter_name>\\w+)[ _](?P<operator>\\w+)', column_name)
        if match is None:
            raise ValueError(f'[{column_name}]: bad format')

        filter_name, operator = match.groups()
        tag_filter = asset_tag_filters.get(filter_name)

        if tag_filter is None:
            raise KeyError(f'[{filter_name}]: filter name not found')

        if operator not in tag_filter['operators']:
            raise KeyError(f'[{operator}]: not in {tag_filter["operators"]}')

    return filter_name, operator


def build_filters(columns, asset_tag_filters: dict):
    '''Build the filter statement based on multiple columns.'''
    header_fields = ('category', 'value', 'filter_type')
    # filter items are all k, v pairs execept
    filter_values = {k: v for k, v in columns.items() if k not in header_fields}
    filters = []
    for field_name, field_value in filter_values.items():
        filter_name, operator = parse_filter_name(field_name, asset_tag_filters)
        if field_value is None:
            continue

        field_value = re.sub('\n+', ',', field_value.strip())
        field_value = re.sub('[ ]*,[ ]*', ',', field_value)

        filters.append((filter_name, operator, field_value))


    # build a record with only the header file
    record = {k: v for k, v in columns.items() if k in header_fields}
    record['filters'] = filters

    return record


def process_groups_from_users(records):

    membership = defaultdict(list)
    group_commands = []

    for user in records:
        if 'groups' not in user['record']:
            continue

        # build group commands and membership index
        try:
            for group_name in user['record']['groups'].split(','):
                membership[group_name].append(user['record']['username'])
        except:
            pass

    # build group 'create'
    for group_name in membership:
        group_cmd = {
            'api_name': 'groups',
            'action': 'create',
            'record': {'name': group_name}
        }
        group_commands.append(group_cmd)

    # build group 'add_user' from membership info
    for group_name, members in membership.items():
        usernames = sorted([u for u in members])
        for name in usernames:
            group_cmd = {
                'api_name': 'groups',
                'action': 'add_user',
                'record': {
                    'group_id': None,
                    'user_id': None,
                    'group_name': group_name,
                    'username': name
                }
            }
            group_commands.append(group_cmd)

    return group_commands


def post_process_sheets(sheets: Dict[str, list], asset_tag_filters: dict = None, action: str = None):
    '''Process sheets to do things build filters from columns and identify groups within user records

    Args:
        sheets: lists of records for each sheet, indexed by sheet name
        asset_tag_filters: valid tag filters from tio.filters.asset_tag_filters()

    '''

    for name, records in sheets.items():
        # we may have to convert the sheetname, i.e. tags_ipv4 or ipv4_tags to tags
        api_name = str_to_api_name(name)

        # generate a password for each user record
        if api_name == 'users':
            records = map(insert_password, records)

        # build filter parameters from columns
        if api_name == 'tags' and asset_tag_filters is not None:
            # records = map(build_filters, records)
            records = [build_filters(record, asset_tag_filters) for record in records]

        def encapsulate(r):
            return {'api_name': api_name, 'action': r.get('action', action), 'record': r}

        sheets[name] = [encapsulate(r) for r in records]

    # expand 'group create' and 'group add user' for groups defined in the user records
    if 'users' in sheets:
        groups = process_groups_from_users(sheets['users'])
        if 'groups' in sheets:
            sheets['groups'].append(groups)
        else:
            sheets['groups'] = groups

    # combine multiple sheets of tags in to a single 'tags' entry
    tag_sheets = {k: v for k, v in sheets.items() if k.startswith('tags') or k.endswith('tags')}
    tag_records = [record for records in tag_sheets.values() for record in records]

    # remove identified tag_sheets from sheets, add combined lists of records to sheets['tags']
    for name in list(tag_sheets):
        del sheets[name]
    sheets['tags'] = tag_records

    return sheets



@action.group(help="Deploy Navi Services using prebuilt Docker Containersr")
def deploy():
    pass


@action.command(help="Push a command to a linux target")
@click.option('--command', default=None, help="Command you want to run in double-quotes")
@click.option('--target', required=True, help="Target IP receiving the command")
@click.option('--file', default=None, help="Push a file to a target")
def push(command, target, file):
    try:
        credentials = db_query("select username, password from ssh;")
        user = credentials[0][0]
        password = credentials[0][1]
        if file:
            scp(user, target, password, file)
        else:
            connect(user, target, password, command)

    except Exception as E:
        click.echo("\nPlease use the 'navi ssh' command to enter your ssh credentials\n"
                   "\nIf you have, then this host may not be a Linux machine or your Credentials are not working\n"
                   "\nHere is the Error: {}\n".format(E))


@action.command(help="Mail yourself a Report")
@click.option("--message", default='', help="Email a custom message or use result of a navi command")
@click.option("--to", default='', help="Email address to send to")
@click.option("--subject", default='', help="Subject of the Email")
@click.option("-v", is_flag=True, help="Display a copy of the message")
@click.option("--file", default=None, help="The name of the file you want to attach to the email")
def mail(message, to, subject, v, file):
    try:
        # grab SMTP information
        server, port, from_email, password = grab_smtp()
        if to == '':
            to = input("Please enter the email you wish send this mail to: ")
        if subject == '':
            subject = input("Please enter the Subject of the email : ")

        subject += " - Emailed by navi"

        if v:
            click.echo("Here is a copy of your email that was Sent")
            click.echo(message)

        send_attachment(from_email, to, server, password, port, file, message, subject)

    except Exception as E:
        click.echo("Your Email information may be incorrect")
        click.echo("Run the 'SMTP' command to correct your information")
        click.echo(E)


@action.command(help="Choose your export type --> assets: '-a' or vulns: '-v' with the corresponding UUID")
@click.argument('uuid')
@click.option('-a', '-assets', is_flag=True, help="Cancel a Asset export using the UUID")
@click.option('-v', '-vulns', is_flag=True, help="Cancel a Vulnerability Export using the UUID")
def cancel(uuid, a, v):
    if not a and not v:
        click.echo("\n You need to signify which export type: '-a' or '-v'")
    if a:
        asset_response = request_data('POST', '/assets/export/{}/cancel'.format(uuid))
        click.echo(asset_response)

    if v:
        vuln_response = request_data('POST', '/vulns/export/{}/cancel'.format(uuid))
        click.echo(vuln_response)


@action.group(help="Delete objects from Tenable IO")
def delete():
    pass


@delete.command(help="Delete assets by Tag: tag_category:tag_value - Example - OS:Linux")
@click.argument('tag_string')
def bytag(tag_string):
    tag_tuple = tag_string.split(':')
    cat = tag_tuple[0]
    val = tag_tuple[1]
    if bytag != '':
        click.echo("\nI'm deleting all of the assets associated with your Tag\n")
        payload = {'query': {'field': "tag.{}".format(cat), 'operator': 'set-has', 'value': str(val)}}
        request_data('POST', '/api/v2/assets/bulk-jobs/delete', payload=payload)


@delete.command(help='Delete a Scan by Scan ID')
@click.argument('tid')
def scan(tid):
    click.echo("\nI'm deleting your Scan Now")
    tio.scans.delete(str(tid))


@delete.command(help='Delete a target-group by target-group ID')
@click.argument('tid')
def tgroup(tid):
    click.echo("\nI'm deleting your Target group Now")
    tio.target_groups.delete(str(tid))


@delete.command(help='Delete a Policy by Policy ID')
@click.argument('tid')
def policy(tid):
    click.echo("\nI'm deleting your Policy Now")
    tio.policies.delete(str(tid))


@delete.command(help='Delete an Asset by Asset UUID')
@click.argument('tid')
def asset(tid):
    click.echo("\nI'm deleting your asset Now")
    tio.assets.delete(str(tid))


@delete.command(help='Delete Tag Value by Value UUID')
@click.argument('tid')
def value(tid):
    click.echo("\nI'm deleting your Tag Value")
    tio.tags.delete(str(tid))


@delete.command(help='Delete Tag Category by Category UUID')
@click.argument('tid')
def category(tid):
    click.echo("\nI'm Deleting your Category")
    tio.tags.delete_category(str(tid))


@delete.command(help='Delete a user by User ID - Not UUID')
@click.argument('tid')
def user(tid):
    click.echo("\nI'm Deleting the User you requested")
    tio.users.delete(str(tid))


@delete.command(help='Delete a user group by the Group ID')
@click.argument('tid')
def usergroup(tid):
    click.echo("\nI'm Deleting the User you requested")
    tio.groups.delete(str(tid))


@delete.command(help='Delete a tag by Category/Value pair')
@click.option('--c', default='', required=True, help="Category to delete")
@click.option('--v', default='', required=True, help="Value to Delete")
def tag(c, v):
    tagdata = request_data('GET', '/tags/values')
    for tags in tagdata['values']:
        if c == tags['category_name']:
            if v == tags['value']:
                value_uuid = tags['uuid']
                request_no_response('DELETE', '/tags/values/' + str(value_uuid))


@delete.command(help='Delete a Network by Network ID')
@click.argument('nid')
def network(nid):
    click.echo("\nI'm deleting your Network now")
    tio.networks.delete(nid)


@action.command(help="Automate Navi tasks from a Spreadsheet")
@click.option('--name', default='tio-config.xls', help='Name of the excel file')
@click.option('-v', is_flag=True, help="enable Verbosity and print navi commands to the screen")
@click.option('--sheet', required=True, type=click.Choice(['users', 'networks', 'agent_groups',
                                                           'tags_fqdn', 'tags_ipv4', 'exclusions',
                                                           'advanced_tags', 'scanner_groups', 'permissions',
                                                           'tags_for_os'], case_sensitive=False),
              multiple=True)
@click.option('--threads', default=10, help="Number of threads to use for any navi updates")
@click.option('-skip', is_flag=True, help="Skip a navi update because it was updated once today already")
def automate(sheet, name, v, threads, skip):
    try:
        ws = Excel(name, sheet_names=sheet)
        _records = ws.get_records()

    except Exception as E:
        click.echo("\nYou need to save the 'tio-config.xlsx' file to begin the automation process.\n")
        click.echo("\nIf you are using python3.9 you will need to safe the file as an XLS instead of XLSX")
        print(E)
        exit()

    if 'users' in sheet:
        print("Creating Groups")
        print("-" * 30)
        for group in _records['groups']:
            time.sleep(1)
            if group['action'] == 'create':
                if v:
                    print("navi config user group create --name \"{}\"".format(group['record']['name']))

                cmd("navi config user group create --name \"{}\"".format(group['record']['name']))

        print("\nCreating users")
        print("-" * 30)
        for user in _records['users']:
            time.sleep(1)
            if v:
                print("navi config user add --username \"{}\" --password \"{}\" --permission {} --name \"{}\" --email \"{}\"".format(
                    user['record']['username'], user['record']['password'], user['record']['permissions'],
                    user['record']['name'], user['record']['email']))

            cmd("navi config user add --username \"{}\" --password \"{}\" --permission {} --name \"{}\" --email \"{}\"".format(
                user['record']['username'], user['record']['password'], user['record']['permissions'],
                user['record']['name'], user['record']['email']))

        print("\nWait two mins")
        time.sleep(120)
        print("\nAdding Users to Groups")
        print("-" * 30)

        for group in _records['groups']:
            time.sleep(1)
            if group['action'] == 'add_user':
                if v:
                    print("navi config user group add --name \"{}\" --user \"{}\"".format(group['record']['group_name'],
                                                                                group['record']['username']))
                # Now add the user to the group
                cmd("navi config user group add --name \"{}\" --user \"{}\"".format(group['record']['group_name'],
                                                                            group['record']['username']))

    if 'networks' in sheet:
        print("\nCreating networks")
        print("-" * 30)
        for net in _records['networks']:
            time.sleep(1)
            if v:
                print("navi config network new --name \"{}\" --d \"{}\"".format(net['record']['network_name'],
                                                                       net['record']['description']))
            cmd("navi config network new --name \"{}\" --d \"{}\"".format(net['record']['network_name'],
                                                                   net['record']['description']))

        print("\nWait two mins")
        time.sleep(120)
        print("\nAdjusting TTL per network")
        print("-" * 30)
        for net in _records['networks']:
            if v:
                print("navi config network change --name \"{}\" --age {}".format(net['record']['network_name'],
                                                                        net['record']['assets_ttl_days']))
            cmd("navi config network change --name \"{}\" --age {}".format(net['record']['network_name'],
                                                                    net['record']['assets_ttl_days']))

    if 'agent_groups' in sheet:
        print("\nCreating Agent groups")
        print("-" * 30)

        for agp in _records['agent_groups']:
            time.sleep(1)
            if v:
                print("navi action agent create --name \"{}\" ".format(agp['record']['group_name']))

            cmd("navi action agent create --name \"{}\" ".format(agp['record']['group_name']))

    if "tags_for_os" in sheet:
        print("\nCreating OS Tags")
        print("-" * 30)
        for tag in _records['tags']:
            if v:
                print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"operating_system\" "
                      "--value \"{}\"".format(tag['record']['tag_category'], tag['record']['tag_value'],
                                              tag['record']['operating_system']))

            cmd("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"operating_system\" "
                "--value \"{}\"".format(tag['record']['tag_category'], tag['record']['tag_value'],
                                        tag['record']['operating_system']))

    if "tags_fqdn" in sheet:
        print("\nCreating FQDN Tags")
        print("-" * 30)
        for tag in _records['tags']:

            if "," in tag['record']['fqdn']:
                if v:
                    print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"fqdn\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))

                cmd("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"fqdn\" --value \"{}\"".format(
                    tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))
            else:
                if v:
                    print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"match\" --filter \"fqdn\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))

                cmd("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"match\" --filter \"fqdn\" --value \"{}\"".format(
                    tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))

        click.echo("Done")

    if "tags_ipv4" in sheet:
        print("\nCreating IPv4 Tags")
        print("-" * 30)
        for tag in _records['tags']:

            if "," in tag['record']['ipv4']:
                if v:
                    print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"ipv4\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

                cmd("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"ipv4\" --value \"{}\"".format(
              tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))
            else:
                if v:
                    print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"ipv4\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

                cmd("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"ipv4\" --value \"{}\"".format(
              tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

        click.echo("Done")

    if 'exclusions' in sheet:
        print("\nCreating Exclusions")
        print("-" * 30)

        for exc in _records['exclusions']:
            if v:
                print("navi config exclude --name \"{}\" --members \"{}\" --start \"{}\" --end \"{}\" --freq {} --day {}".format(
                    exc['record']['exclusion_name'], exc['record']['exclusion_ipv4'], exc['record']['start_time'],
                    exc['record']['end_time'], exc['record']['frequency'], exc['record']['day_of_month']))

            cmd("navi config exclude --name \"{}\" --members \"{}\" --start \"{}\" --end \"{}\" --freq {} --day {}".format(
                exc['record']['exclusion_name'], exc['record']['exclusion_ipv4'], exc['record']['start_time'],
                exc['record']['end_time'], exc['record']['frequency'], exc['record']['day_of_month']))

            print()

    if 'advanced_tags' in sheet:
        if not skip:
            print("\nUpdating navi to refresh the db")
            cmd("navi update full --threads {}".format(threads))
        print("\nCreating Advanced Tags")
        print("-" * 30)

        for ad in _records['tags']:
            time.sleep(1)
            if ad['record']['option'] == 'output':
                if v:
                    print("navi enrich tag --c \"{}\" --v \"{}\" --{} \"{}\" --{} \"{}\"".format(
                        ad['record']['tag_category'], ad['record']['tag_value'], ad['record']['method'],
                        ad['record']['search_string'], ad['record']['option'], ad['record']['option_text']))

                cmd("navi enrich tag --c \"{}\" --v \"{}\" --{} \"{}\" --{} \"{}\"".format(
                    str(ad['record']['tag_category']), str(ad['record']['tag_value']), str(ad['record']['method']),
                    str(ad['record']['search_string']), str(ad['record']['option']), str(ad['record']['option_text'])))
            else:
                if v:
                    print("navi enrich tag --c \"{}\" --v \"{}\" --\"{}\" \"{}\"".format(ad['record']['tag_category'],
                                                                                ad['record']['tag_value'],
                                                                                ad['record']['method'],
                                                                                ad['record']['search_string']))

                cmd("navi enrich tag --c \"{}\" --v \"{}\" --\"{}\" \"{}\"".format(str(ad['record']['tag_category']),
                                                                              str(ad['record']['tag_value']),
                                                                              str(ad['record']['method']),
                                                                              str(ad['record']['search_string'])))

    if 'scanner_groups' in sheet:
        print("\nCreating Scanner groups")
        print("-" * 30)
        for sg in _records['scanner_groups']:
            time.sleep(1)
            if v:
                print("navi config scan-group create --name \"{}\"".format(sg['record']['name']))

            cmd("navi config scan-group create --name \"{}\"".format(sg['record']['name']))

    if 'permissions' in sheet:
        print("\nCreating Permissions")
        print("-" * 30)
        for perms in _records['permissions']:
            if perms['record']['user']:
                print("\nCreating User permission based on tag: {}:{}".format(perms['record']['Tag Category'],
                                                                              perms['record']['Tag Value']))
                if v:
                    print("navi config access create --c \"{}\" --v \"{}\" --user \"{}\" --permlist \"{}\"".format(
                        perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['user'],
                        perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))

                cmd("navi config access create --c \"{}\" --v \"{}\" --user \"{}\" --permlist \"{}\"".format(
                    perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['user'],
                    perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))

            if perms['record']['usergroup']:
                print("\nCreating UserGroup permission based on tag: {}:{}".format(perms['record']['Tag Category'], perms['record']['Tag Value']))

                if v:
                    print("navi config access create --c \"{}\" --v \"{}\" --usergroup \"{}\" --permlist \"{}\"".format(
                        perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['usergroup'],
                        perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))

                cmd("navi config access create --c \"{}\" --v \"{}\" --usergroup \"{}\" --permlist \"{}\"".format(
                    perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['usergroup'],
                    perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))


@deploy.command(help="Deploy navi enrich tag Center using a Docker container: navigate to http://localhost:5000")
def tag_center():
    if click.confirm('This command downloads the packetchaos/tag-center docker container and runs it on port 5000 '
                     'using the current navi database. Deploy?'):
        try:
            os.system("docker run -d -p 5000:5000 --mount type=bind,source=\"$(pwd)\",target=/usr/src/app/data "
                      "packetchaos/tag-center")
        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Was Reporter using a Docker container: navigate to http://localhost:5004")
@click.option("--days", default=60, help="Limit the amount of data being downloaded/reported")
def was_reporter(days):
    a, s = grab_keys()
    command = "docker run -d -p 5004:5004 -e \"access_key={}\" -e \"secret_key={}\" -e {} --mount type=bind,source=$(pwd),target=/usr/src/app/data packetchaos/navi_was_reports".format(a,s,days)
    if click.confirm('This command downloads the packetchaos/navi_was_reports docker container and runs it on port 5004 using the current navi database. Deploy?'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Scantime Tagging solution")
def scan_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/scantags".format(a,s)
    if click.confirm('This command downloads the packetchaos/scantags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Discovery then Vuln Scan solution")
@click.option('--trigger', default=None, help="The Scan ID you want to use as the the Trigger Scan, "
                                                          "or the first scan in the chain.")
@click.option('--fire', default=None, help="The scan ID you want to use for your Vuln Scan")
@click.option('--targets', default=None, help='The subnet(s) you want to run the discovery scan on.')
def discovery_then_vulnscan(trigger, fire, targets):
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} -e trigger={} -e fire={} -e targets={} packetchaos/discovery_then_vulnscan".format(a, s, trigger, fire, targets)
    if click.confirm('This command downloads the packetchaos/discoverythenvulnscan docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Dependency Scan solution")
@click.option('--trigger', default=None, help="The Scan ID you want to use as the the Trigger Scan, "
                                                          "or the first scan in the chain.")
@click.option('--fire', default=None, help="The scan ID you want to use for your Vuln Scan")
def dependency_scan(trigger, fire):
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} -e trigger={} -e fire={} packetchaos/dependency_scan".format(a, s, trigger, fire)
    if click.confirm('This command downloads the packetchaos/discoverythenvulnscan docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Critical Tags Docker solution")
def critical_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/critical_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/critical_tags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Tag each asset by the agent group membership")
def agent_group_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/agent_group_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/agent_group_tags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Tag each asset by the ports found open")
def port_tagging():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/port_tagging".format(a,s)
    if click.confirm('This command downloads the packetchaos/port_tagging docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy the All tags solution.  Deploy all tags from all the navi services")
def all_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/all_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/all_tags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy the User Tags solution")
@click.option('--user', required=True, help="The Scan policy ID you want to use as the the Trigger Scan, "
                                            "or the first scan in the chain.")
def user_tags(user):
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} -e user={} packetchaos/usertags".format(a, s, user)
    if click.confirm('This command downloads the packetchaos/usertags docker container and runs it.  This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Mitre Tags Docker solution")
def mitre_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/mitre_tags".format(a,s)
    if click.confirm('This command downloads the packetchaos/mitre_tags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")
