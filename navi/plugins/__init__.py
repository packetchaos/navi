from .ip import ip
from .find import find
from .display import display
from .delete import delete
from .api import api
from .export import export
from .lumin import lumin
from .update import update
from .add import add
from .scan import scan
from .keys import keys
from .tag import tag
from .network import network
from .user import user
from .usergroup import usergroup
from .target_group import tgroup
from .cancel import cancel
from .migrate import migrate
from .agents import agent
from .access import access
from .attribute import attribute
from .sla import sla
#from .rules import rules
from .cve_compare import compare
from .deploy import deploy
from .was import was
from .agroup import agroup


def plugin_loader(group):
    group.add_command(ip)
    group.add_command(find)
    group.add_command(display)
    group.add_command(delete)
    group.add_command(api)
    group.add_command(export)
    group.add_command(lumin)
    group.add_command(update)
    group.add_command(add)
    group.add_command(scan)
    group.add_command(keys)
    group.add_command(tag)
    group.add_command(network)
    group.add_command(user)
    group.add_command(usergroup)
    group.add_command(tgroup)
    group.add_command(cancel)
    group.add_command(migrate)
    group.add_command(agent)
    group.add_command(access)
    group.add_command(attribute)
    group.add_command(sla)
    #group.add_command(rules)
    group.add_command(compare)
    group.add_command(deploy)
    group.add_command(was)
    group.add_command(agroup)
