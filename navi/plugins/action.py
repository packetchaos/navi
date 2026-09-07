import click
import os
import re
import secrets
import time
import ipaddress
from datetime import datetime
import string
import pandas as pd
import numpy as np
from .dbconfig import (create_keys_table, create_diff_table, create_assets_table, create_vulns_table,
                       create_compliance_table, create_plugins_table, create_agents_table, create_sla_table,
                       create_cpes_table)
from .database import new_db_connection, db_query
from .api_wrapper import request_data, request_no_response, tenb_connection
from .send_mail import send_attachment, send_report
from collections import defaultdict
from typing import Optional, Dict, Tuple
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

# Prompt text we ask sudo to print. We only send the stored password when this exact prompt
# shows up - never blindly - so it can't end up on the remote command line (see connect()).
NAVI_SUDO_PROMPT = "NAVI_SUDO_PROMPT:"

# OpenSSH StrictHostKeyChecking policy for every ssh/scp navi spawns.
#   accept-new : record an unknown host on first contact, REFUSE a host whose key has changed
#   yes        : refuse unknown hosts too (pre-seed known_hosts, or run once with accept-new)
# The old behaviour (answer 'yes' to every prompt, ignore changed keys) let anyone on the path
# collect the service-account password, so it is gone.
HOST_KEY_POLICY_DEFAULT = "accept-new"
HOST_KEY_POLICY_STRICT = "yes"

# A push target must be a plain IP address or DNS hostname. ssh treats anything else as an
# argument, and an option such as -oProxyCommand=... runs a shell on the machine running navi
# before any login happens. Targets can come from a shared --targets-file or from the navi-mcp
# tool, so validate them rather than trusting them.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


def valid_target(host):
    # True if 'host' is an IPv4/IPv6 address or a syntactically valid hostname.
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


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


def invalid_targets(hosts):
    # The subset of 'hosts' that fail valid_target(), in order.
    return [h for h in hosts if not valid_target(h)]


def clean_output_and_exit_code(raw):
    # Pull the exit code out of the sentinel line and strip every sentinel-bearing
    # line (the echoed command and its "NAVI_EXIT:<n>" output) from the display text.
    exit_code = None
    match = re.search(NAVI_EXIT_SENTINEL + r":(\d+)", raw)
    if match:
        exit_code = int(match.group(1))

    # The sudo prompt marker is noise too - it only exists so connect() can spot the prompt.
    cleaned = "\n".join(line.replace(NAVI_SUDO_PROMPT, "") for line in raw.splitlines()
                        if NAVI_EXIT_SENTINEL not in line).strip("\r\n")
    return cleaned, exit_code


def sudo_prompt_argument():
    # The -p value as typed on the remote command line. The shell glues the two quoted halves
    # back into NAVI_SUDO_PROMPT, but the *echoed* command line contains the split form - so
    # expect()ing the joined marker can only match sudo's real prompt, never the echo.
    head, tail = NAVI_SUDO_PROMPT[:9], NAVI_SUDO_PROMPT[9:]
    return "'{}''{}'".format(head, tail)


def build_remote_command(command, add_sentinel=True):
    # Returns (effective_command, needs_sudo).
    # When the command uses sudo we switch it to 'sudo -k -p <marker>': -p makes sudo print a
    # marker we can expect() on, and -k drops any cached timestamp so the prompt is
    # deterministic (it appears unless NOPASSWD applies). sudo reads the password from the tty
    # with echo off, so it never lands in the captured output. connect() sends the password
    # ONLY after seeing the marker. The previous version sent it unconditionally, and whenever
    # sudo didn't ask, the login shell ran the password as the next command - echoing it into
    # the output, ~/.bash_history and syslog on every target.
    needs_sudo = re.search(r"\bsudo\b", command) is not None
    effective = (re.sub(r"\bsudo\b", "sudo -k -p {}".format(sudo_prompt_argument()), command, count=1)
                 if needs_sudo else command)
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


def ssh_session(host_key_policy=HOST_KEY_POLICY_DEFAULT):
    # Every pxssh session navi opens goes through here so the host-key policy is never forgotten.
    return pxssh.pxssh(options={"StrictHostKeyChecking": host_key_policy})


def explain_ssh_failure(host, conn_user, key_file=None, host_key_policy=HOST_KEY_POLICY_DEFAULT):
    # pxssh runs ssh with -q, so when the connection fails all we get back is "Could not
    # establish connection to host". Re-run one non-interactive probe (no password is ever
    # offered - BatchMode) and hand the operator ssh's real reason: a changed host key, a
    # refused connection, a bad key file, an unknown host under --strict-host-keys, etc.
    import subprocess
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking={}".format(host_key_policy),
            "-o", "PasswordAuthentication=no", "-l", conn_user]
    if key_file:
        args += ["-i", key_file]
    args += ["--", host, "true"]
    try:
        probe = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except Exception:
        return ""
    text = probe.stderr or ""
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in text or "Host key verification failed" in text:
        if "No " in text and "host key is known" in text:
            return ("host key is not in known_hosts and --strict-host-keys is set - "
                    "add it deliberately, or run once without --strict-host-keys")
        return ("HOST KEY CHANGED since navi last connected to this address - possible "
                "impersonation or a rebuilt host. Verify the host, then run "
                "ssh-keygen -R {} to clear the old key".format(host))
    if "Permission denied" in text:
        # BatchMode refuses password auth, so this is expected when password auth is in
        # use - it just means the transport and host key are fine.
        return ""
    for line in reversed([l.strip() for l in text.splitlines() if l.strip()]):
        if line.lower().startswith("warning:"):
            continue
        return line[:200]
    return ""


def wait_for_host(host, conn_user, password, key_file, max_wait, interval=15, sleeper=None,
                  host_key_policy=HOST_KEY_POLICY_DEFAULT):
    # Poll SSH until the host answers again (used after a reboot). Returns True if it came back
    # within max_wait seconds. 'sleeper' is injectable so tests don't actually sleep.
    sleep = sleeper if sleeper is not None else time.sleep
    waited = 0
    # Give the box a moment to actually start going down before the first probe.
    sleep(interval)
    waited += interval
    while waited <= max_wait:
        try:
            probe = ssh_session(host_key_policy)
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
            wait_online=0, wait_interval=15, sleeper=None,
            host_key_policy=HOST_KEY_POLICY_DEFAULT):
    # Run a command on a single host. Returns a push_result dict.
    is_reboot = looks_like_reboot(command)
    effective, needs_sudo = build_remote_command(command, add_sentinel=not is_reboot)

    # Phase 1 - establish the connection. A failure here means the command NEVER ran, so it is
    # safe to retry (retryable=True). Once we are past this point the remote command executes,
    # and a later failure must NOT be retried - we can't know if a non-idempotent command
    # partially applied.
    try:
        conn = ssh_session(host_key_policy)
        # ssh_key=None behaves exactly like a normal password login; a path adds ssh -i <key>.
        conn.login(host, conn_user, password, ssh_key=key_file)
    except pxssh.ExceptionPxssh as e:
        reason = str(e)
        detail = explain_ssh_failure(host, conn_user, key_file, host_key_policy)
        if detail:
            reason = "{} ({})".format(reason, detail)
        click.echo("  [!] {}: connection failed: {}".format(host, reason))
        # A host-key failure is a security stop, not a transient - never retry through it.
        retryable = "HOST KEY" not in detail and "known_hosts" not in detail
        return push_result(False, note="connect failed: {}".format(reason), retryable=retryable)

    # Phase 2 - the connection is up; the command now runs. Failures below are not retryable.
    try:
        conn.sendline(effective)
        matched = True
        raw = None
        if needs_sudo:
            # Answer sudo only if it actually asks. With NOPASSWD (or a command that never
            # reaches sudo) the shell prompt comes back first and the password is never sent.
            idx = conn.expect([NAVI_SUDO_PROMPT, conn.PROMPT, pexpect.EOF, pexpect.TIMEOUT],
                              timeout=timeout)
            if idx == 0:
                conn.sendline(password)
            elif idx == 1:
                # The command already finished without a password prompt.
                raw = conn.before.decode('utf-8', errors='replace')
            elif idx == 2 and not is_reboot:
                click.echo("  [!] {}: connection closed before the command finished".format(host))
                return push_result(False, note="connection closed")
            elif idx == 3:
                matched = False
                raw = conn.before.decode('utf-8', errors='replace')

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
                                     interval=wait_interval, sleeper=sleeper,
                                     host_key_policy=host_key_policy)
                if back:
                    click.echo("  [OK] {}: back online".format(host))
                    return push_result(True, note="rebooted; back online")
                click.echo("  [FAIL] {}: did not come back within {}s".format(host, wait_online))
                return push_result(False, note="rebooted; did not return in time")
            return push_result(True, note="reboot issued")

        if raw is None:
            matched = conn.prompt(timeout=timeout)
            raw = conn.before.decode('utf-8', errors='replace')
        conn.logout()

        if not matched:
            click.echo("  [!] {}: timed out waiting for the command to finish".format(host))

        # Belt and braces: whatever the remote side echoed, the password never reaches stdout
        # (or, under navi-mcp, the model transcript).
        if password:
            raw = raw.replace(password, "********")
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


def scp(scp_user, host, password, filename, dest, key_file=None, timeout=300,
        host_key_policy=HOST_KEY_POLICY_DEFAULT):
    # Copy a local file to 'dest' on a single host. Returns a push_result dict.
    ssh_new_key_string = 'Are you sure you want to continue connecting'
    remote = "{}@{}:{}".format(scp_user, host, dest)

    try:
        # Pass args as a list so filenames/paths with spaces or shell metacharacters are safe
        # (no shell word-splitting or injection through the interpolated command string).
        # With a key, prepend '-i <key>' and no password prompt is expected - the transfer
        # can go straight to EOF, which the expect lists below now handle.
        # The host-key policy is passed explicitly so scp never asks and we never say 'yes'.
        # '--' ends option parsing so a hostile filename/target can't be read as an scp flag.
        args = (['-o', 'StrictHostKeyChecking={}'.format(host_key_policy)]
                + (['-i', key_file] if key_file else []) + ['--', filename, remote])
        shell = pexpect.spawn('scp', args, timeout=timeout)

        return_code = shell.expect([pexpect.TIMEOUT, ssh_new_key_string, '[Pp]assword:', pexpect.EOF])

        if return_code == 0:
            # Couldn't even connect - the copy never started, so this is safe to retry.
            click.echo("  [!] {}: error connecting (timed out)".format(host))
            return push_result(False, note="scp connect timeout", retryable=True)

        if return_code == 1:
            # Can't happen with the policy above; if it does, refuse rather than accept blindly.
            shell.sendline('no')
            shell.expect(pexpect.EOF)
            click.echo("  [!] {}: host key is not known - refusing to connect".format(host))
            return push_result(False, note="unknown host key")

        elif return_code == 2:
            # Password prompt on first contact (known host, password auth).
            shell.sendline(password)
            shell.expect(pexpect.EOF)
        # return_code 3 -> EOF already (key auth, no prompt) - nothing to send.

        response = shell.before.decode('utf-8', errors='replace')
        if password:
            response = response.replace(password, "********")
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
    return "".join(secrets.choice(password_chars) for _ in range(length))


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


@action.command(help="Rotate a Users API keys")
@click.option('--userid', required=True, help="User ID")
@click.option("-db", required=False, is_flag=True, help="Update keys in the navi database")
def rotate(userid, db):
    click.echo("\nEnsure you copy these Keys!\n")
    # 2337235

    rotating_keys = request_data("PUT", "/users/{}/keys".format(userid))
    if not rotating_keys:
        click.echo("\nKey rotation failed - no keys were returned (check the user id and your permissions)\n")
        return

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
            cur = conn.cursor()
            # The old pair is dead the moment the API rotates it - don't leave it on disk.
            cur.execute('DELETE from keys')
            sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
            cur.execute(sql, key_dict)

        click.echo("\nYour Keys have been rotated and are now enter into the navi.db\n")

    else:
        click.echo(rotating_keys)



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
@click.option('--strict-host-keys', 'strict_host_keys', is_flag=True,
              help="Refuse hosts not already in known_hosts (default: accept a NEW host on first "
                   "contact, but always refuse a host whose key has CHANGED)")
def push(command, target, targets_file, file, dest, run_after, key_file, timeout,
         wait_online, wait_interval, log_path, retries, retry_base, strict_host_keys):
    host_key_policy = HOST_KEY_POLICY_STRICT if strict_host_keys else HOST_KEY_POLICY_DEFAULT
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
        import sys as _sys
        if _sys.platform == "win32":
            click.echo("\nnavi push drives ssh through a pseudo-terminal (pexpect), which does not "
                       "exist on Windows. Run navi from WSL, a Linux/macOS host, or the navi "
                       "Docker image to use push.\n")
        else:
            click.echo("\nnavi push needs the pexpect/pxssh libraries, which aren't available on "
                       "this system (pip install pexpect).\n")
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

    # Refuse the whole run if any target isn't a plain IP/hostname - see valid_target().
    bad = invalid_targets(targets)
    if bad:
        click.echo("\nRefusing to run: these targets are not IP addresses or hostnames:")
        for entry in bad:
            click.echo("  {!r}".format(entry))
        click.echo("Check --target / --targets-file for stray options, quotes or whitespace.\n")
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
                                timeout=timeout, host_key_policy=host_key_policy),
                    retries, retry_base, host)
                log_result(log_path, "copy", host, result,
                           "{} -> {}".format(os.path.basename(file), dest))
                # copy-then-run: only run the follow-up command if the copy succeeded.
                if result.get("ok") and run_after:
                    click.echo("  >> Running on {}: {}".format(host, run_after))
                    result = run_with_retry(
                        lambda: connect(users, host, password, run_after, key_file=key_file,
                                        timeout=timeout, wait_online=wait_online,
                                        wait_interval=wait_interval,
                                        host_key_policy=host_key_policy),
                        retries, retry_base, host)
                    log_result(log_path, "run-after", host, result, run_after)
            else:
                result = run_with_retry(
                    lambda: connect(users, host, password, command, key_file=key_file,
                                    timeout=timeout, wait_online=wait_online,
                                    wait_interval=wait_interval,
                                    host_key_policy=host_key_policy),
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

        # navi.db holds the API keys and the SSH/SMTP passwords - never let it be mailed.
        if file and os.path.basename(file).lower().startswith("navi.db"):
            click.echo("\nRefusing to attach {} - it contains your credentials.\n".format(file))
            return

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


@action.command(help="Encrypt a file for safe transfer")
@click.option("--name", required=True, help="Name of file you want to encrypt")
@click.option("--new_name", default=None, help="The new name of the file. (Optional)")
@click.option("--password", default=None, envvar="NAVI_FILE_PASSWORD",
              help="Password to encrypt with. Prompted for if omitted; NAVI_FILE_PASSWORD is "
                   "also honoured so it never has to sit in shell history or a process list")
@click.option("--force", is_flag=True, help="Overwrite the output file if it already exists")
def encrypt(name, password, new_name, force):
    try:
        import pyAesCrypt
        # Set buffer size
        buffer_size = 128 * 1024  # 128 KB

        if not password:
            password = click.prompt("Password to encrypt with", hide_input=True,
                                    confirmation_prompt=True)

        if new_name is None:
            new_name = name
        output = "{}.aes".format(new_name)
        if os.path.exists(output) and not force:
            click.echo("\n{} already exists - use --force to overwrite it\n".format(output))
            return
        # Encrypt the file (use the provided new name, or default to the original name)
        pyAesCrypt.encryptFile("{}".format(name), output, password, buffer_size)

        click.echo("\nYour file {} was encrypted\n\n".format(new_name))
    except ImportError:
        click.echo("\nYou need to install pyAesCrypt to use this feature\n")
        exit()
    except ValueError as err:
        click.echo("\nAES encrypt Error: {}\n".format(err))


@action.command(help="Decrypt a File encrypted by Navi")
@click.option("--name", required=True, help="Name of file you want to decrypt")
@click.option("--new_name", default=None, help="The new name of the file. (Optional)")
@click.option("--password", default=None, envvar="NAVI_FILE_PASSWORD",
              help="Password the file was encrypted with. Prompted for if omitted; "
                   "NAVI_FILE_PASSWORD is also honoured")
@click.option("--force", is_flag=True, help="Overwrite the output file if it already exists")
def decrypt(name, password, new_name, force):
    try:
        import pyAesCrypt
        # Set buffer size
        buffer_size = 128 * 1024  # 128 KB

        if not password:
            password = click.prompt("Password", hide_input=True)

        if new_name is not None:
            # Use the customer given name
            output = new_name
        elif name.endswith(".aes"):
            # If no name is given, remove '.aes' from the name
            output = name[:-4]
        else:
            click.echo("\n{} doesn't end in .aes - tell me where to write it with --new_name\n".format(name))
            return

        if os.path.exists(output) and not force:
            click.echo("\n{} already exists - use --force to overwrite it\n".format(output))
            return

        pyAesCrypt.decryptFile("{}".format(name), output, password, buffer_size)

    except ImportError:
        click.echo("\nYou need to install pyAesCrypt to use this feature\n")
        exit()
    except ValueError:
        click.echo("\nWrong Password or the file is corrupted\n\n")


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
@click.option('-y', '--yes', is_flag=True, help="Skip the confirmation prompt")
def bytag(tag_string, yes):
    if ":" in tag_string:
        # Split on the FIRST colon only - tag values can contain ':' themselves
        # ('Owner:team:web' is category 'Owner', value 'team:web', not value 'team').
        cat, val = tag_string.split(':', 1)
        if val != '':
            # Show what is about to go before deleting it - this is irreversible.
            count = db_query("select count(distinct asset_uuid) from tags "
                             "where tag_key=? and tag_value=?;", (cat, val))
            known = count[0][0] if count else "an unknown number of"
            click.echo("\nThis deletes every asset tagged {}:{} ({} assets in navi.db) from "
                       "Tenable VM. It cannot be undone.".format(cat, val, known))
            if not yes and not click.confirm("Continue?", default=False):
                click.echo("Aborted.\n")
                return

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
