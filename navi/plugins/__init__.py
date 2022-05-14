from .ip import ip
from .find import find
from .cs import cs
from .display import display
from .mac import mac
from .delete import delete
from .api import api
from .export import export
from .lumin import lumin
from .update import update
from .add import add
from .scan import scan
from .http import http
from .listen import listen
from .keys import keys
from .smtp import smtp
from .mail import mail
from .tag import tag
from .agroup import agroup
from .was import was
from .network import network
from .user import user
from .usergroup import usergroup
from .target_group import tgroup
from .cancel import cancel
from .migrate import migrate
from .agents import agent
from .push import push
from .ssh import ssh
from .scan_evaluation import evaluate
from .access import access
from .attribute import attribute
from .calculate import calculate
from .sla import sla


def plugin_loader(group):
    group.add_command(ip)
    group.add_command(find)
    group.add_command(cs)
    group.add_command(display)
    group.add_command(mac)
    group.add_command(delete)
    group.add_command(api)
    group.add_command(export)
    group.add_command(lumin)
    group.add_command(update)
    group.add_command(add)
    group.add_command(scan)
    group.add_command(http)
    group.add_command(listen)
    group.add_command(keys)
    group.add_command(smtp)
    group.add_command(mail)
    group.add_command(tag)
    group.add_command(agroup)
    group.add_command(was)
    group.add_command(network)
    group.add_command(user)
    group.add_command(usergroup)
    group.add_command(tgroup)
    group.add_command(cancel)
    group.add_command(migrate)
    group.add_command(agent)
    group.add_command(push)
    group.add_command(ssh)
    group.add_command(evaluate)
    group.add_command(access)
    group.add_command(attribute)
    group.add_command(calculate)
    group.add_command(sla)

