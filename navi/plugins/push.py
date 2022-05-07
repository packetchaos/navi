import pexpect
import click
from .database import db_query


PROMPT = ['#', '>>> ', '> ', '\$ ']


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


def connect(user, host, password):
    ssh_new_key_string = 'Are you sure you want to continue connecting'
    ssh_login_string = 'ssh {}@{}'.format(user, host)

    shell = pexpect.spawn(ssh_login_string)

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
    shell.expect(PROMPT)
    return shell


def scp(user, host, password, filename):
    ssh_new_key_string = 'Are you sure you want to continue connecting'
    scp_login_string = 'scp {} {}@{}:/'.format(filename, user, host)

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


@click.command(help="Push a command to a linux target")
@click.option('--command', default='', required=True, help="Command you want to run in double-quotes")
@click.option('--target', default='', required=True, help="Target IP receiving the command")
@click.option('--wait', is_flag=True, help="Wait for longer commands")
@click.option('--file', default=None, help="Push a file to a target")
def push(command, target, wait, file):

    try:
        credentials = db_query("select username, password from ssh;")
        user = credentials[0][0]
        password = credentials[0][1]
        if file:
            scp(user, target, password, file)
        else:
            shell = connect(user, target, password)

            if wait:
                send_command(shell, command, quick=0)
            else:
                send_command(shell, command, quick=1)

    except Exception as E:
        click.echo("Please use the 'navi ssh' command to enter your ssh credentials\n "
                   "If you have, then this host may not be a Linux machine or your Credentials are not working\n"
                   "Here is the Error: {}".format(E))
