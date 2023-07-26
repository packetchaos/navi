import pexpect
from pexpect import pxssh
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
