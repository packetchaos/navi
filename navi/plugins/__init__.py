from .ip import ip
from .find import find
from .report import report
from .list import display
from .pause import pause
from .start import start
from .stop import stop
from .resume import resume
from .mac import mac
from .delete import delete
from .status import status
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
from .new_tag import tag
from .agroup import agroup
from .navi_portal import portal
from .was import was
from .change import change
from .network import network
from .user import user
from .group import usergroup


def plugin_loader(group):
    group.add_command(ip)
    group.add_command(find)
    group.add_command(report)
    group.add_command(display)
    group.add_command(pause)
    group.add_command(resume)
    group.add_command(start)
    group.add_command(stop)
    group.add_command(mac)
    group.add_command(delete)
    group.add_command(status)
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
    group.add_command(portal)
    group.add_command(was)
    group.add_command(change)
    group.add_command(network)
    group.add_command(user)
    group.add_command(usergroup)
