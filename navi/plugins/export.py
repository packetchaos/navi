import click
import csv
import sys
import textwrap
from .database import db_query
from .query_export import query_export
from .agent_group_export import agent_group_export
from .user_export import user_export
from .query_export_32K import export_query
from .api_wrapper import request_xml
from .export_utils import csv_path
from .agent_to_db import download_agent_data
from restfly import errors as resterrors


# ---------------------------------------------------------------------------
# Output file naming - one convention for every `navi export` subcommand.
#
#   --file   the output file name.  The '.csv' extension is optional; the
#            writer normalizes it (see export_utils.csv_path).
#
# Older per-command spellings ('--filename' on `agents`, '--name' on `parsed`)
# are kept as hidden aliases so existing scripts keep working.  They print a
# deprecation notice and are scheduled for removal in navi 9.0.
# ---------------------------------------------------------------------------


def output_file(default):
    """The standard --file option, applied to every export subcommand."""
    return click.option('--file', 'file', default=default, show_default=True,
                        help="Output file name; the '.csv' extension is optional")


def output_file_with_alias(default, flag):
    """--file plus a hidden, deprecated spelling.  Resolve with resolve_file()."""
    def decorator(command):
        command = click.option(flag, 'file_alias', default=None, hidden=True,
                               help="Deprecated alias for --file")(command)
        command = click.option('--file', 'file', default=None,
                               help="Output file name; the '.csv' extension is "
                                    "optional  [default: {}]".format(default))(command)
        return command
    return decorator


def resolve_file(file, file_alias, flag, default):
    """Precedence: --file  >  deprecated alias  >  the command default."""
    if file_alias is not None:
        click.echo("\nNOTE: '{}' is deprecated and will be removed in navi 9.0; "
                   "use '--file' instead.".format(flag))
        if file is not None:
            click.echo("Both '{}' and '--file' were supplied; "
                       "using '--file'.\n".format(flag))
            return file
        return file_alias
    return file if file is not None else default


@click.group(help="Export tenable VM Data")
def export():
    pass


@export.command(help="Export All Asset data in the Navi Database to a CSV")
@output_file("asset_data")
def assets(file):
    asset_query = "select * from assets;"
    query_export(asset_query, file)


@export.command(help="Export All Agent data into a CSV")
@output_file_with_alias("agent_data", '--filename')
def agents(file, file_alias):
    name = resolve_file(file, file_alias, '--filename', "agent_data")
    download_agent_data()
    agent_query = "select * from agents;"
    query_export(agent_query, name)


@export.command(help="Export Licensed Assets into a CSV")
@output_file("licensed_data")
def licensed(file):
    licensed_query = ("SELECT ip_address, fqdn, uuid, last_licensed_scan_date "
                      "from assets where last_licensed_scan_date != ' ';")
    query_export(licensed_query, file)


@export.command(help="Export All assets of a given network")
@click.argument('network_uuid')
@output_file("network_data")
def network(network_uuid, file):
    network_query = "SELECT * from assets where network=='{}';".format(network_uuid)
    query_export(network_query, file)


@export.command(help='Export assets or vulns by a query')
@click.argument('statement')
@output_file("query_data")
@click.option('-fix', is_flag=True, help="Fix for Vuln Outputs with over 32K chars")
def query(statement, file, fix):
    if fix:
        export_query(statement, file)
    else:
        query_export(statement, file)


@export.command(help='Export Agents by Group name')
@click.argument('group_name')
@output_file("agent_group_data")
def group(group_name, file):
    click.echo("\nExporting agents in group '{}'...".format(group_name))
    written = agent_group_export(group_name, file)
    click.echo("\nWrote {}\n".format(written))


@export.command(help="Export All assets by tag; Include ACR and AES into a CSV")
@click.option('--c', required=True, help="Export bytag with the following Category name")
@click.option('--v', required=True, help="Export bytag with the Tag Value; "
                                                       "requires --c and Category Name")
@output_file("bytag")
def bytag(c, v, file):
    tag_assets = ("SELECT assets.*, tags.asset_uuid FROM assets JOIN tags ON assets.uuid = tags.asset_uuid "
                  "WHERE tags.tag_key='" + c + "' AND tags.tag_value='" + v + "';")

    query_export(tag_assets, file)


@export.command(help="Export User and Role information into a CSV")
@output_file("user_data")
def users(file):
    click.echo("\nExporting User Data now...")
    written = user_export(file)
    click.echo("\nWrote {}\n".format(written))


@export.command(help="Export Compliance information into a CSV")
@click.option('--name', default=None, help="FILTER: exact name of the Audit file to be "
                                           "exported.  Use 'navi display audits' to "
                                           "get the right name.  (This filters the export; "
                                           "use --file to name the output.)")
@click.option('--uuid', default=None, help="UUID of the Asset for your export")
@output_file("compliance_data")
def compliance(name, uuid, file):
    click.echo("\nExporting your requested Compliance data into a CSV\n")
    try:
        if name and uuid:
            export_query("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                         "assets.uuid = compliance.asset_uuid "
                         "where compliance.audit_file='{}' "
                         "and compliance.asset_uuid='{}';".format(name, uuid), name=file)
        elif name:
            export_query("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                         "assets.uuid = compliance.asset_uuid "
                         "where audit_file='{}';".format(name), name=file)

        elif uuid:
            export_query("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                         "assets.uuid = compliance.asset_uuid "
                         "where asset_uuid='{}';".format(uuid), name=file)

        else:
            export_query("SELECT assets.fqdn, compliance.* FROM compliance LEFT OUTER JOIN assets ON "
                         "assets.uuid = compliance.asset_uuid;", name=file)

    except AttributeError:
        click.echo("\nCheck your permissions or your API keys\n")
    except resterrors.ForbiddenError:
        click.echo("\nYou do not have access to this endpoint. Check with your Tenable VM Admin.\n")


@export.command(help="Export All Vulnerability data in the Navi Database to a CSV")
@output_file("vuln_data")
@click.option('--c', default=None, help="Export by tag with the following Category name")
@click.option('--v', default=None, help="Export by tag with the Tag Value; requires --c and Category Name")
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low', 'info'],
                                              case_sensitive=False), multiple=True, help="Export vulns by severity")
@click.option('--plugin', default=None, help="Export vulns by plugin ID")
@click.option('--name', default=None, help="FILTER: export vulns with text or REGEX in the "
                                           "plugin name.  Use --file to name the output.")
@click.option('--output', default='', help="Export vulns with text or REGEX in the plugin output")
@click.option('--cve', default='', help="Export vulns by CVE ID")
@click.option('--xrefs', default=None, help="Export vulns by Cross References like 'CISA'")
@click.option('-regexp', is_flag=True, help="Use a Regular expression instead of a "
                                            "text search; requires another option(name, output, cve, xrefs")
def vulns(file, severity, c, v, plugin, output, regexp, name, cve, xrefs):
    try:
        asset_query = "Error"
        if severity:
            # Severity options Chosen
            if c and v:
                asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns "
                               "left join tags on vulns.asset_uuid = tags.asset_uuid and "
                               "tags.tag_key='{}' and tags.tag_value='{}' "
                               "left join plugins on vulns.plugin_id = plugins.plugin_id "
                               "left join zipper on plugins.plugin_id = zipper.plugin_id "
                               "where severity in {};".format(c, v, severity))
            elif plugin:
                # Severity and plugin conflict
                click.echo("\nSeverity can only be chosen alone or with a Tag\n")
                exit()
            elif output:
                # Severity and plugin conflict
                click.echo("\nSeverity can only be chosen alone or with a Tag.\n")
                exit()
            elif regexp:
                # Severity and plugin conflict
                click.echo("\nSeverity can only be chosen alone or with a Tag.\n")
                exit()
            elif xrefs:
                # Severity and plugin conflict
                click.echo("\nSeverity can only be chosen alone or with a Tag.\n")
                exit()
            elif cve:
                # Severity and plugin conflict
                click.echo("\nSeverity can only be chosen alone or with a Tag.\n")
                exit()
            else:
                # No tag, just a severity
                asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns "
                               "left join plugins on vulns.plugin_id = plugins.plugin_id "
                               "left join zipper on plugins.plugin_id = zipper.plugin_id "
                               "where severity in {};").format(severity)

        else:
            # No Severity Chosen
            if c and v:
                if plugin:
                    if output:
                        # Tag, plugin ID and output
                        if regexp:

                            # Enable regex
                            asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                           "vulns.asset_uuid = tags.asset_uuid and "
                                           "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                           "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                           "plugins.plugin_id = zipper.plugin_id where vulns.plugin_id='{}' and "
                                           "vulns.output REGEXP '{}';".format(c, v, plugin, output))
                        else:
                            # no regex
                            asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                           "vulns.asset_uuid = tags.asset_uuid and "
                                           "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                           "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                           "plugins.plugin_id = zipper.plugin_id where vulns.plugin_id='{}' and "
                                           "vulns.output LIKE '%{}%';".format(c, v, plugin, output))
                    else:
                        # Tag and plugin id
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.plugin_id='{}';".format(c, v, plugin))
                elif output:
                    # Tag, plugin ID and output
                    if regexp:
                        # Enable regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.output REGEXP '{}';".format(c, v, output))
                    else:
                        # no regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.output LIKE '%{}%';".format(c, v, output))

                elif name:
                    # Tag and text in plugin name
                    if regexp:
                        # Enable regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.plugin_name REGEXP '{}';".format(c, v, name))
                    else:
                        # no regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.plugin_name LIKE '%{}%';".format(c, v, name))
                elif xrefs:
                    if regexp:
                        # Enable regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.xrefs REGEXP '{}';".format(c, v, xrefs))
                    else:
                        # no regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.xrefs LIKE '%{}%';".format(c, v, xrefs))
                elif cve:
                    if regexp:
                        # Enable regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.cves REGEXP '{}';".format(c, v, cve))
                    else:
                        # no regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                       "vulns.asset_uuid = tags.asset_uuid and "
                                       "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.cves LIKE '%{}%';".format(c, v, cve))
                else:
                    # Just the Tag data
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join tags on "
                                   "vulns.asset_uuid = tags.asset_uuid and "
                                   "tags.tag_key='{}' and tags.tag_value='{}' left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id;".format(c, v))
            elif plugin:
                if output:
                    # plugin ID and output
                    if regexp:
                        # Enable regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id where vulns.plugin_id='{}' and "
                                       "vulns.output REGEXP '{}';".format(plugin, output))
                    else:
                        # no regex
                        asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                       "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                       "plugins.plugin_id = zipper.plugin_id "
                                       "where vulns.plugin_id='{}' and "
                                       "vulns.output LIKE '%{}%';".format(plugin, output))
                else:
                    # Just Plugin ID
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id where vulns.plugin_id={};".format(plugin))
            elif output:
                if regexp:
                    # Enable regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id "
                                   "where vulns.output REGEXP '{}';".format(output))
                else:
                    # no regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id "
                                   "where vulns.output LIKE '%{}%';".format(output))

            elif name:
                # Tag and text in plugin name
                if regexp:
                    # Enable regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns "
                                   "left join plugins on vulns.plugin_id = plugins.plugin_id "
                                   "left join zipper on plugins.plugin_id = zipper.plugin_id "
                                   "where vulns.plugin_name REGEXP '{}';".format(name))
                else:
                    # no regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id "
                                   "where vulns.plugin_name LIKE '%{}%';".format(name))
            elif xrefs:
                if regexp:
                    # Enable regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id where vulns.xrefs REGEXP '{}';".format(xrefs))
                else:
                    # no regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id where vulns.xrefs LIKE '%{}%';".format(xrefs))
            elif cve:
                if regexp:
                    # Enable regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id where vulns.cves REGEXP '{}';".format(cve))
                else:
                    # no regex
                    asset_query = ("select vulns.*, plugins.*, zipper.epss_value from vulns left join plugins on"
                                   "vulns.plugin_id = plugins.plugin_id left join zipper on"
                                   "plugins.plugin_id = zipper.plugin_id where vulns.cves LIKE '%{}%';".format(cve))
            else:
                all_vulns = ("select vulns.*, plugins.*, zipper.epss_value from vulns "
                             "left join plugins on vulns.plugin_id = plugins.plugin_id "
                             "left join zipper on plugins.plugin_id = zipper.plugin_id;")

                if not sys.stdin.isatty():
                    # Non-interactive caller (pipe, cron, navi-mcp): there is
                    # nobody to answer the prompt, so "no filters" means
                    # "export everything" instead of aborting.
                    asset_query = all_vulns
                else:
                    try:
                        answered = click.confirm(
                            'You didn\'t make a selection...Use "--help" to see all options.\n'
                            'Do you want to Export all vulns?\n')
                    except click.Abort:
                        # isatty() can still report a terminal when stdin is
                        # inherited but unreadable (notably a Windows
                        # subprocess). Click raises Abort on EOF but returns
                        # False on an explicit "n", so Abort specifically means
                        # "nobody could answer" -- not "the user declined".
                        answered = True
                    if answered:
                        asset_query = all_vulns

        click.echo("\nExporting your data now; with the following query:\n{}\n".format(asset_query))
        query_export(asset_query, file)
    except UnboundLocalError:
        exit()


@export.command(help="Export Vulnerabilities that have failed")
@output_file("sla_backlog")
def failures(file):
    click.echo("\nExporting All vulnerabilities that failed your SLA\n This requires you run 'navi update fixed'")
    query_export("select * from fixed where pass_fail=='Fail' and state !='FIXED';", file)



def parsed(file, file_alias, user_names):
    name = resolve_file(file, file_alias, '--name', "parsed_plugin_data")

    if not user_names:
        click.echo("\nNothing to parse.  Use '-user_names' to parse the 45478 "
                   "plugin for local user accounts.\n")
        return

    path = csv_path(name)
    with open(path, mode='w', encoding='utf-8', newline="") as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        header = ['Asset_UUID', "User Found"]
        agent_writer.writerow(header)

        if user_names:
            raw_data = db_query("select asset_uuid, output from vulns where plugin_id='45478'")

            # pprint.pprint(eval(str(raw_data))[1][1])
            plugin_data = eval(str(raw_data))

            for asset in plugin_data:
                # remove the +users in the beginning of the string
                output_data = asset[1][18:]

                # Split the users at "|"
                output_data_split = str(output_data).split("|")

                for user in output_data_split:
                    user_list = []
                    strip_output = str(user).strip()

                    if "Computer" not in strip_output:
                        split_output = strip_output.split(",")[0][3:]

                        if asset[0]:
                            user_list.append(asset[0])
                            user_list.append(str(split_output))

                            agent_writer.writerow(user_list)

    click.echo("\nWrote {}\n".format(path))


@export.command(help="Export policies for a migration")
@click.option('--pid', required=True,
              help="Policy ID to be exported. Use 'navi display policies' for IDs")
@click.option('--file', 'file', default=None,
              help="Output file name; the '.nessus' extension is optional  "
                   "[default: the policy ID]")
def policy(pid, file):
    # Policies come back as .nessus rather than CSV, but the naming contract
    # is the same: caller gives a name, the writer owns the extension.
    path = csv_path(file if file else pid, extension="nessus")
    policy_data = request_xml('GET', '/policies/{}/export'.format(pid))
    with open(path, 'w') as policy_file:
        policy_file.write(str(policy_data))
    click.echo("\nWrote {}\n".format(path))

@export.command(help="Export vulnerabilities by route ID")
@click.argument('route_id')
@click.option('--file', 'file', default=None,
              help="Output file name; the '.csv' extension is optional  "
                   "[default: route_<route_id>]")
def route(route_id, file):
    route_info = db_query("select plugin_list from vuln_route where route_id='{}'".format(route_id))

    work = str(route_info[0][0]).replace("[", "(").replace("]", ")")

    vulns_to_route = ("select vulns.*, plugins.*, zipper.epss_value from vulns "
                      "left join plugins on vulns.plugin_id = plugins.plugin_id "
                      "left join zipper on plugins.plugin_id = zipper.plugin_id where "
                      "vulns.plugin_id in {} and vulns.severity !='info';".format(work))

    export_query(vulns_to_route, file if file else "route_{}".format(route_id))
