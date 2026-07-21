import click
import os
import re
import random
import time
from datetime import datetime
import string
import pandas as pd
import numpy as np
from .dbconfig import (create_keys_table, create_diff_table, create_assets_table, create_vulns_table,
                       create_compliance_table, create_plugins_table, create_agents_table, create_sla_table,
                       create_cpes_table)
from .dbconfig import create_rules_table
from .database import new_db_connection, db_query, insert_rules
from .api_wrapper import request_data, request_no_response, tenb_connection
from .send_mail import send_attachment, send_report
from collections import defaultdict
from typing import Optional, Dict, Tuple
from os import system as cmd
from .error_msg import error_msg
from restfly import errors as resterrors
from .tone_tag_helper import grab_tone_asset_list, tone_remove_tag
try:
    # this is only needed for an obscure component of navi.  navi push...
    import pexpect
    from pexpect import pxssh
except ImportError:
    pexpect = 0
    pxssh = 0
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
        except Exception:
            click.echo("\nYou don't have any API keys!  Please enter your keys\n")
            exit()
        rows = cur.fetchall()
        if not rows:
            click.echo("\nYou don't have any API keys!  Please enter your keys\n")
            exit()
        access_key = secret_key = None
        for row in rows:
            access_key = row[0]
            secret_key = row[1]

    return access_key, secret_key


def delete_table(tbl):
    be_gone = db_query("DELETE from {}".format(tbl))

    click.echo("\nDeleting the data in the {} Table.\n{}".format(tbl, be_gone))


def grab_smtp():
    try:
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
    except IndexError:
        click.echo("\nYou need to enter smtp information\n")


def send_command(shell, command, quick):
    if quick == 1:
        shell.sendline(command)
        shell.expect(PROMPT)
    else:
        shell.sendline(command)
        shell.expect(PROMPT, timeout=300)
        shell.expect(pexpect.TIMEOUT)

    response = shell.before
    click.echo()
    # decode defensively - remote output may contain non-UTF-8 bytes (locale, binary, colour codes)
    print(response.decode('utf-8', errors='replace'))
    click.echo()


# Sentinel we append to every pushed command so we can read the remote exit status back.
NAVI_EXIT_SENTINEL = "NAVI_EXIT"


def parse_targets(target):
    # Split a --target value into an ordered, de-duplicated list of hosts.
    # Accepts a single IP or a comma-separated list ("10.0.0.1, 10.0.0.2").
    seen = set()
    hosts = []
    for piece in (target or "").split(','):
        host = piece.strip()
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def clean_output_and_exit_code(raw):
    # Pull the exit code out of the sentinel line and strip every sentinel-bearing
    # line (the echoed command and its "NAVI_EXIT:<n>" output) from the display text.
    exit_code = None
    match = re.search(NAVI_EXIT_SENTINEL + r":(\d+)", raw)
    if match:
        exit_code = int(match.group(1))

    cleaned = "\n".join(line for line in raw.splitlines()
                        if NAVI_EXIT_SENTINEL not in line).strip("\r\n")
    return cleaned, exit_code


def build_remote_command(command, add_sentinel=True):
    # Returns (effective_command, needs_sudo).
    # When the command uses sudo we switch it to 'sudo -S -p ""' so sudo reads the password
    # from stdin and prints no prompt - this avoids waiting on a prompt that never matches the
    # shell PROMPT (the old code blocked for the full timeout) and never sends the password as a
    # bare shell command line when sudo doesn't actually ask for it.
    needs_sudo = re.search(r"\bsudo\b", command) is not None
    effective = re.sub(r"\bsudo\b", "sudo -S -p ''", command, count=1) if needs_sudo else command
    # Append the exit-status sentinel; '$?' reflects the exit code of the pushed command.
    # Reboot commands skip this - the session dies before the echo could ever run.
    if add_sentinel:
        effective = "{} ; echo {}:$?".format(effective, NAVI_EXIT_SENTINEL)
    return effective, needs_sudo


def looks_like_reboot(command):
    # Commands that tear down the SSH session on purpose. For these, the connection dropping
    # right after we send the command is the success signal - there is no exit status to read.
    return re.search(r"\b(reboot|init\s+6|halt|poweroff)\b", command) is not None \
        or re.search(r"\bshutdown\b\s+-r", command) is not None


def push_result(ok, exit_code=None, note="", retryable=False):
    # Uniform per-host result so push() can print, summarise and log the same shape.
    # 'retryable' is True ONLY for transport failures that happened before the remote command
    # ran (e.g. the SSH login failed), so a retry cannot double-apply a non-idempotent command.
    return {"ok": bool(ok), "exit_code": exit_code, "note": note, "retryable": bool(retryable)}


# Backoff defaults for --retries. base is the first delay; each attempt doubles it up to the cap.
RETRY_FACTOR = 2
RETRY_MAX_DELAY = 60


def retry_delay(attempt, base, factor=RETRY_FACTOR, max_delay=RETRY_MAX_DELAY):
    # Exponential backoff for retry number 'attempt' (1-based): base, base*factor, ... capped.
    return min(base * (factor ** (attempt - 1)), max_delay)


def run_with_retry(operation, retries, base, host, sleeper=None):
    # Run 'operation' (a zero-arg callable returning a push_result dict), retrying ONLY when the
    # result is not ok AND flagged retryable (a pre-execution transport failure). Records the
    # number of attempts on the returned result. With retries=0 this calls once and returns.
    sleep = sleeper if sleeper is not None else time.sleep
    attempt = 0
    while True:
        result = operation()
        if result.get("ok") or not result.get("retryable") or attempt >= retries:
            result["attempts"] = attempt + 1
            return result
        attempt += 1
        delay = retry_delay(attempt, base)
        click.echo("  ... transient failure on {} - retry {}/{} in {}s".format(
            host, attempt, retries, delay))
        sleep(delay)


def wait_for_host(host, conn_user, password, key_file, max_wait, interval=15, sleeper=None):
    # Poll SSH until the host answers again (used after a reboot). Returns True if it came back
    # within max_wait seconds. 'sleeper' is injectable so tests don't actually sleep.
    sleep = sleeper if sleeper is not None else time.sleep
    waited = 0
    # Give the box a moment to actually start going down before the first probe.
    sleep(interval)
    waited += interval
    while waited <= max_wait:
        try:
            probe = pxssh.pxssh()
            probe.login(host, conn_user, password, ssh_key=key_file, login_timeout=10)
            probe.logout()
            return True
        except Exception:
            sleep(interval)
            waited += interval
    return False


def log_result(log_path, action, host, result, detail):
    # Append one tab-separated row per host to the run log. Best-effort: a logging failure
    # must never abort the push run.
    if not log_path:
        return
    try:
        new_file = not os.path.exists(log_path)
        with open(log_path, "a") as handle:
            if new_file:
                handle.write("timestamp\thost\taction\tresult\texit_code\tattempts\tdetail\n")
            handle.write("{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                datetime.now().isoformat(timespec="seconds"),
                host, action,
                "OK" if result.get("ok") else "FAIL",
                "" if result.get("exit_code") is None else result.get("exit_code"),
                result.get("attempts", 1),
                detail))
    except Exception as E:
        click.echo("  [!] could not write to log '{}': {}".format(log_path, E))


def grab_ssh_credentials():
    # Returns (username, password, key_file) or None.
    # Tries the current 3-column schema first, then falls back to the older 2-column ssh
    # table so navi.db files created before key auth still work without a re-config.
    try:
        rows = db_query("select username, password, key_file from ssh;")
        if rows:
            return rows[0][0], rows[0][1], rows[0][2]
    except Exception:
        pass
    try:
        rows = db_query("select username, password from ssh;")
        if rows:
            return rows[0][0], rows[0][1], None
    except Exception:
        pass
    return None


def read_targets_file(path):
    # One target per line; blank lines and '#' comments (including inline) are ignored.
    # Each line may itself be a comma-separated list - de-duplication happens in parse_targets.
    lines = []
    with open(path) as handle:
        for line in handle:
            line = line.split('#', 1)[0].strip()
            if line:
                lines.append(line)
    return lines


def connect(conn_user, host, password, command, key_file=None, timeout=300,
            wait_online=0, wait_interval=15, sleeper=None):
    # Run a command on a single host. Returns a push_result dict.
    is_reboot = looks_like_reboot(command)
    effective, needs_sudo = build_remote_command(command, add_sentinel=not is_reboot)

    # Phase 1 - establish the connection. A failure here means the command NEVER ran, so it is
    # safe to retry (retryable=True). Once we are past this point the remote command executes,
    # and a later failure must NOT be retried - we can't know if a non-idempotent command
    # partially applied.
    try:
        conn = pxssh.pxssh()
        # ssh_key=None behaves exactly like a normal password login; a path adds ssh -i <key>.
        conn.login(host, conn_user, password, ssh_key=key_file)
    except pxssh.ExceptionPxssh as e:
        click.echo("  [!] {}: connection failed: {}".format(host, e))
        return push_result(False, note="connect failed: {}".format(e), retryable=True)

    # Phase 2 - the connection is up; the command now runs. Failures below are not retryable.
    try:
        conn.sendline(effective)
        if needs_sudo:
            # Consumed by 'sudo -S' on stdin; not echoed, so it never appears in the output.
            conn.sendline(password)

        if is_reboot:
            # The reboot tears down the session - the connection dropping is the success signal,
            # so we wait briefly for EOF rather than for a shell prompt that will never return.
            try:
                conn.expect(pexpect.EOF, timeout=min(timeout, 60))
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            click.echo("  [OK] {}: reboot issued".format(host))

            if wait_online:
                click.echo("  ... waiting up to {}s for {} to come back online".format(
                    wait_online, host))
                back = wait_for_host(host, conn_user, password, key_file, wait_online,
                                     interval=wait_interval, sleeper=sleeper)
                if back:
                    click.echo("  [OK] {}: back online".format(host))
                    return push_result(True, note="rebooted; back online")
                click.echo("  [FAIL] {}: did not come back within {}s".format(host, wait_online))
                return push_result(False, note="rebooted; did not return in time")
            return push_result(True, note="reboot issued")

        matched = conn.prompt(timeout=timeout)
        raw = conn.before.decode('utf-8', errors='replace')
        conn.logout()

        if not matched:
            click.echo("  [!] {}: timed out waiting for the command to finish".format(host))

        output, exit_code = clean_output_and_exit_code(raw)
        if output:
            click.echo(output)

        if exit_code is None:
            click.echo("  [?] {}: command ran but the exit status could not be read".format(host))
            return push_result(False, exit_code=None, note="no exit status")
        if exit_code == 0:
            click.echo("  [OK] {}: exit 0".format(host))
            return push_result(True, exit_code=0)
        click.echo("  [FAIL] {}: exit {}".format(host, exit_code))
        return push_result(False, exit_code=exit_code)
    except pxssh.ExceptionPxssh as e:
        click.echo("  [!] {}: {}".format(host, e))
        return push_result(False, note=str(e))


def scp(scp_user, host, password, filename, dest, key_file=None, timeout=300):
    # Copy a local file to 'dest' on a single host. Returns a push_result dict.
    ssh_new_key_string = 'Are you sure you want to continue connecting'
    remote = "{}@{}:{}".format(scp_user, host, dest)

    try:
        # Pass args as a list so filenames/paths with spaces or shell metacharacters are safe
        # (no shell word-splitting or injection through the interpolated command string).
        # With a key, prepend '-i <key>' and no password prompt is expected - the transfer
        # can go straight to EOF, which the expect lists below now handle.
        args = (['-i', key_file] if key_file else []) + [filename, remote]
        shell = pexpect.spawn('scp', args, timeout=timeout)

        return_code = shell.expect([pexpect.TIMEOUT, ssh_new_key_string, '[Pp]assword:', pexpect.EOF])

        if return_code == 0:
            # Couldn't even connect - the copy never started, so this is safe to retry.
            click.echo("  [!] {}: error connecting (timed out)".format(host))
            return push_result(False, note="scp connect timeout", retryable=True)

        if return_code == 1:
            shell.sendline('yes')
            second_return_code = shell.expect([pexpect.TIMEOUT, '[Pp]assword:', pexpect.EOF])

            if second_return_code == 0:
                click.echo("  [!] {}: error connecting after accepting host key (timed out)".format(host))
                return push_result(False, note="scp connect timeout after host-key accept",
                                   retryable=True)
            # second_return_code 1 -> password prompt; 2 -> EOF (key auth finished, nothing to send)
            if second_return_code == 1:
                shell.sendline(password)
                shell.expect(pexpect.EOF)

        elif return_code == 2:
            # Password prompt on first contact (known host, password auth).
            shell.sendline(password)
            shell.expect(pexpect.EOF)
        # return_code 3 -> EOF already (key auth, no prompt) - nothing to send.

        response = shell.before.decode('utf-8', errors='replace')
        if response.strip():
            click.echo(response.strip())

        shell.close()
        if shell.exitstatus == 0:
            click.echo("  [OK] {}: '{}' copied to {}".format(host, os.path.basename(filename), dest))
            return push_result(True, exit_code=0)
        click.echo("  [FAIL] {}: scp exited {}".format(host, shell.exitstatus))
        return push_result(False, exit_code=shell.exitstatus, note="scp failed")
    except (KeyError, IndexError, TypeError):
        click.echo("\nThis feature requires pexpect. Your system doesn't allow pexpect.spawn "
                   "or pexpect isn't installed.\n")
        return push_result(False, note="pexpect unavailable")


class Excel:
    def __init__(self, file_path: str, sheet_names: Optional[list]= None) -> None:
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
        df = df.map(strip_whitespace)
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
    """
        split value into (filter_name, operator)

        The filter column name will be either:
            - the name of a filter, i.e. ipv4
            - OR the <name><' ' or '_'><operator

    """
    # default to equal when the value is a filter_name without the operator
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
    """Build the filter statement based on multiple columns."""
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


@action.group(help="Deploy Navi Services using prebuilt Docker Containers")
def deploy():
    pass


@action.group(help="Create/Update or Run your Navi Tag Plan")
def plan():
    pass


@action.command(help="Rotate a Users API keys")
@click.option('--userid', required=True, help="User ID")
@click.option("-db", required=False, is_flag=True, help="Update keys in the navi database")
def rotate(userid, db):
    click.echo("\nEnsure you copy these Keys!\n")
    # 2337235

    rotating_keys = request_data("PUT", "/users/{}/keys".format(userid))
    click.echo(rotating_keys)

    if db:
        # Create all the tables on key rotation
        create_keys_table()
        create_diff_table()
        create_vulns_table()
        create_plugins_table()
        create_assets_table()
        create_agents_table()
        create_compliance_table()
        create_sla_table()
        create_cpes_table()

        access_key = rotating_keys['accessKey']
        secret_key = rotating_keys['secretKey']

        key_dict = (access_key, secret_key)
        database = r"navi.db"
        conn = new_db_connection(database)

        with conn:
            sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
            cur = conn.cursor()
            cur.execute(sql, key_dict)

        click.echo("\nYour Keys have been rotated and are now enter into the navi.db\n")

    else:
        click.echo(rotating_keys)


@plan.command(help="Run Navi Tags in Strategic Groups")
@click.option('--c', required=True, help="Category of your Tag Rule")
@click.option('--v', required=True, help="Value of your Tag Rule")
@click.option('--d', required=False, help='Tag Description')
@click.option('--method', required=True, type=click.Choice(['plugin', 'name', 'group', 'output',
                                                            'scantime', 'scanid', 'query', 'cve', 'xrefs',
                                                            'route_id', 'cpe']), help="Navi Tagging method")
@click.option('--method_text', required=True, help="Test to pair with the Chosen Method")
@click.option('--option_one', required=False, type=click.Choice(['plugin', 'histid', 'xid', 'xref-id',
                                                                 'by_tag', 'by_cat', 'by_val']),
              help="Navi option that alters the current Method")
@click.option('--option_text', required=False, help="Text to pair with Option One alteration")
@click.option('--option_two', required=False, type=click.Choice(['tone', 'regexp']),
              help="Option to create a TOne Tag or use regular expressions")
@click.option('--option_three', required=False, type=click.Choice(['tone', 'regexp']),
              help="Option to create a TOne Tag or use regular expressions")
def create(c, v, d, method, method_text, option_one, option_text, option_two, option_three):
    # Insert into DB
    create_rules_table()

    database_conn = new_db_connection(r"navi.db")
    with database_conn:
        today = datetime.now()
        date_in_d = str((d or "") + "Updated: {}".format(str(today)))
        navi_tag_rule = [None, str(c), str(v), date_in_d, method, str(method_text), option_one, str(option_text), option_two, option_three, str(today), None]

        insert_rules(database_conn, navi_tag_rule)


@plan.command(help="Run your Strategic Navi Tag Rules")
def run():

    # Grab data from the database
    rules_data = db_query("select * from rules;")

    for rule_i in rules_data:
        # Map the Data
        c = rule_i[1]
        v = rule_i[2]
        d = rule_i[3]
        method = rule_i[4]
        method_text = rule_i[5]
        option_one = rule_i[6]
        option_text = rule_i[7]
        option_two = rule_i[8]
        option_three = rule_i[9]

        if d:
            if option_one:
                if option_two:
                    if option_three:
                        click.echo("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}' -{} -{}".format(c,
                                                                                                            v,
                                                                                                            d,
                                                                                                            method,
                                                                                                            method_text,
                                                                                                            option_one,
                                                                                                            option_text,
                                                                                                            option_two,
                                                                                                            option_three))

                        cmd("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}' -{} -{}".format(c,
                                                                                                                   v,
                                                                                                                   d,
                                                                                                                   method,
                                                                                                                   method_text,
                                                                                                                   option_one,
                                                                                                                   option_text,
                                                                                                                   option_two,
                                                                                                                   option_three))
                    else:
                        click.echo("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}' -{}".format(c, v, d,
                                                                                                        method,
                                                                                                        method_text,
                                                                                                        option_one,
                                                                                                        option_text,
                                                                                                        option_two))

                        cmd("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}' -{}".format(c, v, d,
                                                                                                        method,
                                                                                                        method_text,
                                                                                                        option_one,
                                                                                                        option_text,
                                                                                                        option_two))
                else:
                    click.echo("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}'".format(c, v, d, method,
                                                                                              method_text,
                                                                                              option_one,
                                                                                              option_text))
                    cmd("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}'".format(c, v, d, method,
                                                                                              method_text,
                                                                                              option_one,
                                                                                              option_text))
            else:
                click.echo("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}'".format(c, v, d, method, method_text))
                cmd("navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}'".format(c, v, d, method, method_text))
        elif option_one:
            if option_two:
                if option_three:
                    click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}' -{} -{}".format(c,
                                                                                               v,
                                                                                               method,
                                                                                               method_text,
                                                                                               option_one,
                                                                                               option_text,
                                                                                               option_two,
                                                                                               option_three))
                    cmd("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}' -{} -{}".format(c,
                                                                                                      v,
                                                                                                      method,
                                                                                                      method_text,
                                                                                                      option_one,
                                                                                                      option_text,
                                                                                                      option_two,
                                                                                                      option_three))
                else:
                    click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}' -{}".format(c, v,
                                                                                           method,
                                                                                           method_text,
                                                                                           option_one,
                                                                                           option_text,
                                                                                           option_two))
                    cmd("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}' -{}".format(c, v,
                                                                                           method,
                                                                                           method_text,
                                                                                           option_one,
                                                                                           option_text,
                                                                                           option_two))
            else:
                click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}'".format(c, v, method,
                                                                                 method_text,
                                                                                 option_one,
                                                                                 option_text))
                cmd("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}'".format(c, v, method,
                                                                                 method_text,
                                                                                 option_one,
                                                                                 option_text))
        elif option_two:
            if option_three:
                click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' -{} -{}".format(c,
                                                                                 v,
                                                                                 method,
                                                                                 method_text,
                                                                                 option_two,
                                                                                 option_three))
                cmd("navi enrich tag --c '{}' --v '{}' --{} '{}' -{} -{}".format(c,
                                                                                        v,
                                                                                        method,
                                                                                        method_text,
                                                                                        option_two,
                                                                                        option_three))
            else:
                click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' -{}".format(c, v,
                                                                           method,
                                                                           method_text,
                                                                           option_two))
                cmd("navi enrich tag --c '{}' --v '{}' --{} '{}' -{}".format(c, v,
                                                                           method,
                                                                           method_text,
                                                                           option_two))

        else:
            if option_three:
                click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' -{}".format(c,
                                                                             v,
                                                                             method,
                                                                             method_text,
                                                                             option_three))
                cmd("navi enrich tag --c '{}' --v '{}' --{} '{}' -{}".format(c,
                                                                                    v,
                                                                                    method,
                                                                                    method_text,
                                                                                    option_three))
            else:
                click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}'".format(c, v, method, method_text))
                cmd("navi enrich tag --c '{}' --v '{}' --{} '{}'".format(c, v, method, method_text))


@plan.command(help="Import Tag Rules from Tag Sheet")
@click.option('--file', required=True, help="CSV tio-config.csv")
def ingest(file):
    import csv
    create_rules_table()
    with open(file, 'r', newline='') as new_file:
        rules_sheet = csv.reader(new_file)

        database_conn = new_db_connection(r"navi.db")
        click.echo()
        click.echo("-" * 50)
        click.echo("Tag Rules Imported into Rules Table")
        click.echo("-" * 50)
        click.echo()
        with database_conn:
            today = time.time()
            for row in rules_sheet:
                # Skip the Header Row
                if str(row[0]) == 'tag_category':
                    pass
                else:
                    # Map the Data
                    c = row[0]
                    v = row[1]
                    method = row[2]
                    method_text = row[3]
                    option_one = row[4]
                    option_text = row[5]
                    navi_tag_rule = [None, row[0], row[1], None, row[2], row[3], row[4], row[5], None, None, today, None]
                    insert_rules(database_conn, navi_tag_rule)

                    if option_one:
                        click.echo("navi enrich tag --c '{}' --v '{}' --{} '{}' --{} {}".format(c, v, method,
                                                                                                method_text,
                                                                                                option_one,
                                                                                                option_text))

                    else:
                        click.echo("navi enrich tag --c '{}' --v '{}' --{} {} ".format(c, v, method, method_text))


@plan.command(help="List Tag Rules")
def display():
    # Grab data from the database
    try:
        rules_data = db_query("select * from rules;")

        click.echo("Rule ID - Navi Command - You can copy and paste the command in your CLI to test.")
        click.echo("-" * 150)
        for rule_instance in rules_data:
            # Map the Data
            ruleid = rule_instance[0]
            c = rule_instance[1]
            v = rule_instance[2]
            d = rule_instance[3]
            method = rule_instance[4]
            method_text = rule_instance[5]
            option_one = rule_instance[6]
            option_text = rule_instance[7]
            option_two = rule_instance[8]
            option_three = rule_instance[9]

            if d:
                if option_one:
                    if option_two:
                        if option_three:
                            click.echo(
                                "{} - navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}' -{} -{}".format(ruleid, c,
                                                                                                                v,
                                                                                                                d,
                                                                                                                method,
                                                                                                                method_text,
                                                                                                                option_one,
                                                                                                                option_text,
                                                                                                                option_two,
                                                                                                                option_three))

                        else:
                            click.echo("{} - navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} '{}' -{}".format(ruleid, c, v, d,
                                                                                                            method,
                                                                                                            method_text,
                                                                                                            option_one,
                                                                                                            option_text,
                                                                                                            option_two))
                    else:
                        click.echo("{} - navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}' --{} {}".format(ruleid, c, v, d, method,
                                                                                                  method_text,
                                                                                                  option_one,
                                                                                                  option_text))
                else:
                    click.echo("{} - navi enrich tag --c '{}' --v '{}' --d '{}' --{} '{}'".format(ruleid, c, v, d, method, method_text))
            elif option_one:
                if option_two:
                    if option_three:
                        click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}' -{} -{}".format(ruleid, c,
                                                                                                          v,
                                                                                                          method,
                                                                                                          method_text,
                                                                                                          option_one,
                                                                                                          option_text,
                                                                                                          option_two,
                                                                                                          option_three))
                    else:
                        click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} '{}' --{} '{}' -{}".format(ruleid, c, v,
                                                                                                      method,
                                                                                                      method_text,
                                                                                                      option_one,
                                                                                                      option_text,
                                                                                                      option_two))
                else:
                    click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} '{}' --{} {}".format(ruleid, c, v, method,
                                                                                            method_text,
                                                                                            option_one,
                                                                                            option_text))
            elif option_two:
                if option_three:
                    click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} '{}' -{} -{}".format(ruleid, c,
                                                                                            v,
                                                                                            method,
                                                                                            method_text,
                                                                                            option_two,
                                                                                            option_three))
                else:
                    click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} {} -{}".format(ruleid, c, v,
                                                                                      method,
                                                                                      method_text,
                                                                                      option_two))

            else:
                if option_three:
                    click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} '{}' -{}".format(ruleid, c,
                                                                                        v,
                                                                                        method,
                                                                                        method_text,
                                                                                        option_three))
                else:
                    click.echo("{} - navi enrich tag --c '{}' --v '{}' --{} {}".format(ruleid, c, v, method, method_text))

    except TypeError:
        click.echo("\nNo rules have been created.")
        exit()


@action.command(help="Push a command or file to one or more Linux targets over SSH")
@click.option('--command', default=None, help="Command you want to run in double-quotes")
@click.option('--target', default=None,
              help="Target IP - a single IP or a comma-separated list (10.0.0.1,10.0.0.2)")
@click.option('--targets-file', 'targets_file', default=None,
              help="Path to a file with one target per line (# comments and blank lines ignored)")
@click.option('--file', default=None, help="Local file to push to the target(s)")
@click.option('--dest', default='~/', show_default=True,
              help="Remote destination path for --file (the SSH user's home by default)")
@click.option('--run-after', 'run_after', default=None,
              help="Command to run on each target after --file is copied (copy-then-run)")
@click.option('--key', 'key_file', default=None,
              help="Path to an SSH private key for key-based auth (overrides the stored password)")
@click.option('--timeout', default=300, show_default=True, type=int,
              help="Seconds to wait for a command/copy to finish (raise it for big updates)")
@click.option('--wait-online', 'wait_online', default=0, type=int,
              help="After a reboot, wait up to N seconds for the host to come back (0 = don't wait)")
@click.option('--wait-interval', 'wait_interval', default=15, show_default=True, type=int,
              help="Seconds between reconnection probes while --wait-online is polling")
@click.option('--log', 'log_path', default=None,
              help="Append per-host results (timestamp, host, action, result, exit code) to this file")
@click.option('--retries', default=0, show_default=True, type=int,
              help="Retry a host on a transport failure (SSH couldn't connect) up to N times. "
                   "Only pre-execution failures are retried - a command that ran and failed is not.")
@click.option('--retry-base', 'retry_base', default=5, show_default=True, type=int,
              help="First retry delay in seconds; it doubles each attempt up to 60s")
def push(command, target, targets_file, file, dest, run_after, key_file, timeout,
         wait_online, wait_interval, log_path, retries, retry_base):
    # Guard the inputs before touching any host.
    if not command and not file:
        click.echo("\nYou need to send a --command or a --file when using this command\n")
        return

    if command and file:
        click.echo("\nSend either --command or --file, not both.\n")
        return

    if run_after and not file:
        click.echo("\n--run-after only applies with --file (copy a file, then run a command).\n")
        return

    if not target and not targets_file:
        click.echo("\nYou need to supply --target and/or --targets-file.\n")
        return

    if pexpect == 0 or pxssh == 0:
        click.echo("\nnavi push needs the pexpect/pxssh libraries, which aren't available on "
                   "this system.\n")
        return

    # Resolve SSH credentials once and reuse them across every target.
    creds = grab_ssh_credentials()
    if not creds:
        click.echo("\nPlease use the 'navi config ssh' command to enter your ssh credentials.\n")
        return
    users, password, stored_key = creds
    # An explicit --key overrides whatever was stored via 'navi config ssh'.
    key_file = key_file or stored_key

    # Collect targets from --target and/or --targets-file, then de-duplicate together.
    raw_sources = []
    if target:
        raw_sources.append(target)
    if targets_file:
        try:
            raw_sources.extend(read_targets_file(targets_file))
        except Exception as E:
            click.echo("\nCould not read --targets-file '{}': {}\n".format(targets_file, E))
            return

    targets = parse_targets(",".join(raw_sources))
    if not targets:
        click.echo("\nNo valid targets found in --target / --targets-file.\n")
        return

    succeeded = 0
    failed = 0
    for host in targets:
        # Audit line so it's always clear what ran where.
        if file:
            click.echo("\n>> Pushing file '{}' to {}:{}".format(os.path.basename(file), host, dest))
        else:
            click.echo("\n>> Running on {}: {}".format(host, command))

        try:
            if file:
                result = run_with_retry(
                    lambda: scp(users, host, password, file, dest, key_file=key_file,
                                timeout=timeout),
                    retries, retry_base, host)
                log_result(log_path, "copy", host, result,
                           "{} -> {}".format(os.path.basename(file), dest))
                # copy-then-run: only run the follow-up command if the copy succeeded.
                if result.get("ok") and run_after:
                    click.echo("  >> Running on {}: {}".format(host, run_after))
                    result = run_with_retry(
                        lambda: connect(users, host, password, run_after, key_file=key_file,
                                        timeout=timeout, wait_online=wait_online,
                                        wait_interval=wait_interval),
                        retries, retry_base, host)
                    log_result(log_path, "run-after", host, result, run_after)
            else:
                result = run_with_retry(
                    lambda: connect(users, host, password, command, key_file=key_file,
                                    timeout=timeout, wait_online=wait_online,
                                    wait_interval=wait_interval),
                    retries, retry_base, host)
                log_result(log_path, "command", host, result, command)
        except Exception as E:
            # Isolate failures so one bad host doesn't abort the rest of the run.
            click.echo("  [!] {}: unexpected error: {}".format(host, E))
            result = push_result(False, note=str(E))
            log_result(log_path, "file" if file else "command", host, result, command or file)

        if result.get("ok"):
            succeeded += 1
        else:
            failed += 1

    if len(targets) > 1:
        click.echo("\nDone. {} succeeded, {} failed, {} total.".format(
            succeeded, failed, len(targets)))
    if log_path:
        click.echo("Run log written to {}".format(log_path))


@action.command(help="Mail yourself a Report - uses Resend when a key is configured")
@click.option("--message", default='', help="Email a custom message or use result of a navi command")
@click.option("--to", default='', help="Email address to send to")
@click.option("--subject", default='', help="Subject of the Email")
@click.option("-v", is_flag=True, help="Display a copy of the message")
@click.option("--file", default=None, help="The name of the file you want to attach to the email")
@click.option("--html", "html_file", default=None,
              help="Path to an HTML file to render as the email body (--message stays the plaintext fallback)")
def mail(message, to, subject, v, file, html_file):
    # Transport is picked automatically: Resend if a key is available (env RESEND_API_KEY or
    # 'navi config resend'), otherwise the classic SMTP path. Setup details in RESEND_SETUP.md
    try:
        if to == '':
            to = input("Please enter the email you wish send this mail to: ")
        if subject == '':
            subject = input("Please enter the Subject of the email : ")

        subject += " - Emailed by navi"

        # Read the HTML page so it can be rendered in the email body instead of attached.
        html_body = None
        if html_file:
            try:
                with open(html_file, "r", encoding="utf-8") as html_fh:
                    html_body = html_fh.read()
            except Exception as html_error:
                click.echo("Could not read the HTML file you supplied with --html")
                click.echo(html_error)
                return

        if v:
            click.echo("Here is a copy of your email that was Sent")
            click.echo(html_body if html_body else message)

        send_report(to, subject, message, filename=file, html=html_body)

    except Exception as E:
        click.echo("Your Email information may be incorrect")
        click.echo("Run the 'navi config resend' or 'navi config smtp' command to correct your information\n")
        click.echo(E)


@action.command(help="Encrypt an file for save transfer")
@click.option("--name", required=True, help="Name of file you want to encrypt")
@click.option("--new_name", default=None, help="The new name of the file. (Optional)")
@click.option("--password", required=True, help="Password you want to encrypt your file with")
def encrypt(name, password, new_name):
    try:
        import pyAesCrypt
        # Set buffer size
        buffer_size = 128 * 1024  # 128 KB

        if new_name is None:
            new_name = name
        # Encrypt the file (use the provided new name, or default to the original name)
        pyAesCrypt.encryptFile("{}".format(name), "{}.aes".format(new_name), password, buffer_size)

        click.echo("\nYour file {} was encrypted\n\n".format(new_name))
    except ImportError:
        click.echo("\nYou need to install pyAesCrypt to use this feature\n")
        exit()
    except ValueError as err:
        click.echo("\nAES encrypt Error: {}\n".format(err))


@action.command(help="Decrypt a File encrypted by Navi")
@click.option("--name", required=True, help="Name of file you want to decrypt")
@click.option("--new_name", default=None, help="The new name of the file. (Optional)")
@click.option("--password", required=True, help="Password you want to decrypt your file with")
def decrypt(name, password, new_name):
    try:
        import pyAesCrypt
        # Set buffer size
        buffer_size = 128 * 1024  # 128 KB
        remove_aes_from_name = name[:-4]
        if new_name is None:
            # If no name is given, remove '.aes' from the name
            remove_aes_from_name = name[:-4]
        else:
            # Use the customer given name
            remove_aes_from_name = new_name

        # Encrypt the file
        pyAesCrypt.decryptFile("{}".format(name), "{}".format(remove_aes_from_name), password, buffer_size)

    except ImportError:
        click.echo("\nYou need to install pyAesCrypt to use this feature\n")
        exit()
    except ValueError:
        click.echo("\nWrong Password of the file is corrupted\n\n")


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


@action.group(help="Delete objects from Tenable Vulnerability Management")
def delete():
    pass


@delete.command(help="Delete all data from a table")
@click.argument('tbl')
def table(tbl):
    delete_table(tbl)


@delete.command(help="Delete assets by Tag: tag_category:tag_value - Example - OS:Linux")
@click.argument('tag_string')
def bytag(tag_string):
    if ":" in tag_string:
        tag_tuple = tag_string.split(':')
        cat = tag_tuple[0]
        val = tag_tuple[1]
        if val != '':

            click.echo("\nI'm deleting all of the assets associated with your Tag\n")
            payload = {'query': {'field': "tag.{}".format(cat), 'operator': 'set-has', 'value': str(val)}}
            request_data('POST', '/api/v2/assets/bulk-jobs/delete', payload=payload)

    else:
        click.echo("\nERROR:\nIt doesn't look like you put the tag in the right format. \n"
                   "Ensure you put the Category and Value in this format: 'tag category:tag value\n"
                   "This is case sensitive.\n")


@delete.command(help='Delete a Scan by Scan ID')
@click.argument('tid')
def scan(tid):
    try:
        click.echo("\nI'm deleting your Scan Now")
        tio.scans.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete a target-group by target-group ID')
@click.argument('tid')
def tgroup(tid):
    try:
        click.echo("\nI'm deleting your Target group Now")
        tio.target_groups.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete a Policy by Policy ID')
@click.argument('tid')
def policy(tid):
    try:
        click.echo("\nI'm deleting your Policy Now")
        tio.policies.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete an Asset by Asset UUID')
@click.argument('tid')
def asset(tid):
    try:
        click.echo("\nI'm deleting your asset Now")
        tio.assets.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete Tag Value by Value UUID')
@click.argument('tid')
def value(tid):
    try:
        click.echo("\nI'm deleting your Tag Value")
        tio.tags.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete Tag Category by Category UUID')
@click.argument('tid')
def category(tid):
    try:
        click.echo("\nI'm Deleting your Category")
        tio.tags.delete_category(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete a user by User ID - Not UUID')
@click.argument('tid')
def user(tid):
    try:
        click.echo("\nI'm Deleting the User you requested")
        tio.users.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help='Delete a user group by the Group ID')
@click.argument('tid')
def usergroup(tid):
    try:
        click.echo("\nI'm Deleting the User you requested")
        tio.groups.delete(str(tid))
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


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
    try:
        click.echo("\nI'm deleting your Network now")
        tio.networks.delete(nid)
    except AttributeError as e:
        error_msg(e)
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@delete.command(help="Delete Tag Rules from your Action Plan")
@click.argument('ruleid')
def rules(ruleid):
    try:
        delete_assets = db_query("DELETE from rules where rowid={}".format(ruleid))
        click.echo("\nYour Rule was deleted {}".format(delete_assets))
    except:
        click.echo("\nYour Rule wasn't found")


@delete.command(help="Delete a Tenable One Tag; Remove assets from a tag.")
@click.option("--c", required =True, help="TONE Category Exact name(case sensitive)")
@click.option("--v", required=True, help="TONE value Exact name(case sensitive)")
@click.option("-remove", is_flag=True, help="Remove Assets from the tag instead")
def tone(c,v, remove):
    from .tone_tag_helper import tag_value_exists
    get_tag_id = tag_value_exists(c,v)

    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    if get_tag_id == 'no':
        click.echo("\nTag does not exist; either it was already deleted or not created at all\n")
    else:

        if remove:
            tag_list = grab_tone_asset_list(c,v)
            if len(tag_list) > 5000:
                # break the list into 2000 IP chunks
                click.echo("\nYour Tag results were over 5000 assets; breaking up the api requests\n")

                for chunks in chunks(tag_list, 5000):
                    tone_remove_tag(chunks, get_tag_id)
            else:
                click.echo("\nI'm Removing assets from your Tag now\n")
                tone_remove_tag(tag_list, get_tag_id)
        else:
            if click.confirm("\nI'm about to delete your Tag are you sure?"):
                click.echo("\nI'm Deleting your tag now\n")
                request_no_response("DELETE", "/api/v1/t1/tags/{}".format(get_tag_id))


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
                    print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" "
                          "--filter \"ipv4\" --value \"{}\"".format(
                        tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))

                cmd("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"nmatch\" --filter \"ipv4\" --value \"{}\"".format(
              tag['record']['tag_category'], tag['record']['tag_value'], tag['record']['ipv4']))
            else:
                if v:
                    print("navi enrich tagrule --c \"{}\" --v \"{}\" --action \"eq\" -"
                          "-filter \"ipv4\" --value \"{}\"".format(tag['record']['tag_category'],
                                                                   tag['record']['tag_value'], tag['record']['ipv4']))

                cmd("navi enrich tagrule "
                    "--c \"{}\" --v \"{}\" --action \"eq\" "
                    "--filter \"ipv4\" --value \"{}\"".format(tag['record']['tag_category'],
                                                              tag['record']['tag_value'], tag['record']['ipv4']))

        click.echo("Done")

    if 'exclusions' in sheet:
        print("\nCreating Exclusions")
        print("-" * 30)

        for exc in _records['exclusions']:
            if v:
                print("navi config exclude --name \"{}\" --members \"{}\" --start \"{}\" --end \"{}\" "
                      "--freq {} --day {}".format(exc['record']['exclusion_name'], exc['record']
                ['exclusion_ipv4'], exc['record']['start_time'], exc['record']['end_time'], exc['record']['frequency'],
                                                  exc['record']['day_of_month']))

            cmd("navi config exclude "
                "--name \"{}\" --members \"{}\" --start \"{}\" "
                "--end \"{}\" --freq {} --day {}".format(exc['record']['exclusion_name'],
                                                         exc['record']['exclusion_ipv4'], exc['record']['start_time'],
                                                         exc['record']['end_time'], exc['record']['frequency'],
                                                         exc['record']['day_of_month']))

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
                    print("navi enrich tag "
                          "--c \"{}\" --v \"{}\" --{} {}".format(ad['record']['tag_category'],
                                                                         ad['record']['tag_value'],
                                                                         ad['record']['method'],
                                                                         ad['record']['search_string']))

                cmd("navi enrich tag "
                    "--c \"{}\" --v \"{}\" --{} {}".format(str(ad['record']['tag_category']),
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
                print("\nCreating UserGroup permission based on tag: "
                      "{}:{}".format(perms['record']['Tag Category'], perms['record']['Tag Value']))

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
    command = ("docker run -d -p 5004:5004 -e \"access_key={}\" -e \"secret_key={}\" -e \"days={}\" "
               "--mount type=bind,source=$(pwd),target=/usr/src/app/data "
               "packetchaos/navi_was_reports").format(a, s, days)
    if click.confirm('This command downloads the packetchaos/navi_was_reports '
                     'docker container and runs it on port 5004 using the current navi database. Deploy?'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Scantime Tagging solution")
def scan_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/scantags".format(a, s)
    if click.confirm('This command downloads the packetchaos/scantags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
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
    command = ("docker run -d -e access_key={} -e secret_key={} -e trigger={} -e fire={} -e targets={} "
               "packetchaos/discovery_then_vulnscan").format(a, s, trigger, fire, targets)
    if click.confirm('This command downloads the packetchaos/discoverythenvulnscan docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
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
    command = ("docker run -d -e access_key={} -e secret_key={} -e trigger={} -e fire={} "
               "packetchaos/dependency_scan").format(a, s, trigger, fire)
    if click.confirm('This command downloads the packetchaos/discoverythenvulnscan docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Critical Tags Docker solution")
def critical_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/critical_tags".format(a, s)
    if click.confirm('This command downloads the packetchaos/critical_tags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Tag each asset by the agent group membership")
def agent_group_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/agent_group_tags".format(a, s)
    if click.confirm('This command downloads the packetchaos/agent_group_tags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Tag each asset by the ports found open")
def port_tagging():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/port_tagging".format(a, s)
    if click.confirm('This command downloads the packetchaos/port_tagging docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy the All tags solution.  Deploy all tags from all the navi services")
def all_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/all_tags".format(a, s)
    if click.confirm('This command downloads the packetchaos/all_tags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
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
    if click.confirm('This command downloads the packetchaos/usertags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")


@deploy.command(help="Deploy Navi Mitre Tags Docker solution")
def mitre_tags():
    a, s = grab_keys()
    command = "docker run -d -e access_key={} -e secret_key={} packetchaos/mitre_tags".format(a, s)
    if click.confirm('This command downloads the packetchaos/mitre_tags docker container and runs it.  '
                     'This will run as a service and will be destroyed after the all assets are tagged.'):
        try:
            os.system(command)

        except os.error:
            click.echo("You might not have Docker installed")
