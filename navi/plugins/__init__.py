from .was import was
from .export import export
from .scan import scan
from .config import config
from .action import action
from .enrich import enrich
from .explore import explore


def plugin_loader(group):
    group.add_command(export)
    group.add_command(scan)
    group.add_command(was)
    group.add_command(config)
    group.add_command(action)
    group.add_command(enrich)
    group.add_command(explore)