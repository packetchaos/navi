import click
import re
import random
import time
import string
import pandas as pd
import numpy as np
from collections import defaultdict
from typing import Optional, Dict, Tuple
from os import system as cmd

PASSWORD_LENGTH = 20


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


@click.command(help="Automate Navi tasks from a Spreadsheet")
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
                    print("navi usergroup create --name \"{}\"".format(group['record']['name']))

                cmd("navi usergroup create --name \"{}\"".format(group['record']['name']))

        print("\nCreating users")
        print("-" * 30)
        for user in _records['users']:
            time.sleep(1)
            if v:
                print("navi user add --username \"{}\" --password \"{}\" --permission {} --name \"{}\" --email \"{}\"".format(
                    user['record']['username'], user['record']['password'], user['record']['permissions'],
                    user['record']['name'], user['record']['email']))

            cmd("navi user add --username \"{}\" --password \"{}\" --permission {} --name \"{}\" --email \"{}\"".format(
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
                    print("navi usergroup add --name \"{}\" --user \"{}\"".format(group['record']['group_name'],
                                                                                group['record']['username']))
                # Now add the user to the group
                cmd("navi usergroup add --name \"{}\" --user \"{}\"".format(group['record']['group_name'],
                                                                            group['record']['username']))

    if 'networks' in sheet:
        print("\nCreating networks")
        print("-" * 30)
        for net in _records['networks']:
            time.sleep(1)
            if v:
                print("navi network new --name \"{}\" --d \"{}\"".format(net['record']['network_name'],
                                                                       net['record']['description']))
            cmd("navi network new --name \"{}\" --d \"{}\"".format(net['record']['network_name'],
                                                                   net['record']['description']))

        print("\nWait two mins")
        time.sleep(120)
        print("\nAdjusting TTL per network")
        print("-" * 30)
        for net in _records['networks']:
            if v:
                print("navi network change --name \"{}\" --age {}".format(net['record']['network_name'],
                                                                        net['record']['assets_ttl_days']))
            cmd("navi network change --name \"{}\" --age {}".format(net['record']['network_name'],
                                                                    net['record']['assets_ttl_days']))

    if 'agent_groups' in sheet:
        print("\nCreating Agent groups")
        print("-" * 30)

        for agp in _records['agent_groups']:
            time.sleep(1)
            if v:
                print("navi agent create --name \"{}\" ".format(agp['record']['group_name']))

            cmd("navi agent create --name \"{}\" ".format(agp['record']['group_name']))

    if "tags_for_os" in sheet:
        print("\nCreating OS Tags")
        print("-" * 30)
        for tag in _records['tags']:
            if v:
                print("navi tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"operating_system\" "
                      "--value \"{}\"".format(tag['record']['tag_category'], tag['record']['tag_value'],
                                              tag['record']['operating_system']))

            cmd("navi tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"operating_system\" "
                "--value \"{}\"".format(tag['record']['tag_category'], tag['record']['tag_value'],
                                        tag['record']['operating_system']))

    if "tags_fqdn" in sheet:
        print("\nCreating FQDN Tags")
        print("-" * 30)
        for tag in _records['tags']:

            if "," in tag['record']['fqdn']:
                if v:
                    print("navi tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"fqdn\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))

                cmd("navi tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"fqdn\" --value \"{}\"".format(
                    tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))
            else:
                if v:
                    print("navi tagrule --c \"{}\" --v \"{}\" --action \"match\" --filter \"fqdn\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))

                cmd("navi tagrule --c \"{}\" --v \"{}\" --action \"match\" --filter \"fqdn\" --value \"{}\"".format(
                    tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['fqdn']))

        click.echo("Done")

    if "tags_ipv4" in sheet:
        print("\nCreating IPv4 Tags")
        print("-" * 30)
        for tag in _records['tags']:

            if "," in tag['record']['ipv4']:
                if v:
                    print("navi tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"ipv4\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

                cmd("navi tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"ipv4\" --value \"{}\"".format(
              tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))
            else:
                if v:
                    print("navi tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"ipv4\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

                cmd("navi tagrule --c \"{}\" --v \"{}\" --action \"eq\" --filter \"ipv4\" --value \"{}\"".format(
              tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

        click.echo("Done")

    if 'exclusions' in sheet:
        print("\nCreating Exclusions")
        print("-" * 30)

        for exc in _records['exclusions']:
            if v:
                print("navi exclude --name \"{}\" --members \"{}\" --start \"{}\" --end \"{}\" --freq {} --day {}".format(
                    exc['record']['exclusion_name'], exc['record']['exclusion_ipv4'], exc['record']['start_time'],
                    exc['record']['end_time'], exc['record']['frequency'], exc['record']['day_of_month']))

            cmd("navi exclude --name \"{}\" --members \"{}\" --start \"{}\" --end \"{}\" --freq {} --day {}".format(
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
                    print("navi tag --c \"{}\" --v \"{}\" --{} \"{}\" --{} \"{}\"".format(
                        ad['record']['tag_category'], ad['record']['tag_value'], ad['record']['method'],
                        ad['record']['search_string'], ad['record']['option'], ad['record']['option_text']))

                cmd("navi tag --c \"{}\" --v \"{}\" --{} \"{}\" --{} \"{}\"".format(
                    str(ad['record']['tag_category']), str(ad['record']['tag_value']), str(ad['record']['method']),
                    str(ad['record']['search_string']), str(ad['record']['option']), str(ad['record']['option_text'])))
            else:
                if v:
                    print("navi tag --c \"{}\" --v \"{}\" --\"{}\" \"{}\"".format(ad['record']['tag_category'],
                                                                                ad['record']['tag_value'],
                                                                                ad['record']['method'],
                                                                                ad['record']['search_string']))

                cmd("navi tag --c \"{}\" --v \"{}\" --\"{}\" \"{}\"".format(str(ad['record']['tag_category']),
                                                                              str(ad['record']['tag_value']),
                                                                              str(ad['record']['method']),
                                                                              str(ad['record']['search_string'])))

    if 'scanner_groups' in sheet:
        print("\nCreating Scanner groups")
        print("-" * 30)
        for sg in _records['scanner_groups']:
            time.sleep(1)
            if v:
                print("navi sgroup create --name \"{}\"".format(sg['record']['name']))

            cmd("navi sgroup create --name \"{}\"".format(sg['record']['name']))

    if 'permissions' in sheet:
        print("\nCreating Permissions")
        print("-" * 30)
        for perms in _records['permissions']:
            if perms['record']['user']:
                print("\nCreating User permission based on tag: {}:{}".format(perms['record']['Tag Category'],
                                                                              perms['record']['Tag Value']))
                if v:
                    print("navi access create --c \"{}\" --v \"{}\" --user \"{}\" --permlist \"{}\"".format(
                        perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['user'],
                        perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))

                cmd("navi access create --c \"{}\" --v \"{}\" --user \"{}\" --permlist \"{}\"".format(
                    perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['user'],
                    perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))

            if perms['record']['usergroup']:
                print("\nCreating UserGroup permission based on tag: {}:{}".format(perms['record']['Tag Category'], perms['record']['Tag Value']))

                if v:
                    print("navi access create --c \"{}\" --v \"{}\" --usergroup \"{}\" --permlist \"{}\"".format(
                        perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['usergroup'],
                        perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))

                cmd("navi access create --c \"{}\" --v \"{}\" --usergroup \"{}\" --permlist \"{}\"".format(
                    perms['record']['Tag Category'], perms['record']['Tag Value'], perms['record']['usergroup'],
                    perms['record']['permission list(CanScan, CanUse, CanEdit, CanView)']))