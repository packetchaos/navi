import click
import textwrap
from sqlite3 import Error
from .api_wrapper import tenb_connection, request_data
from .database import db_query

tio = tenb_connection()


def plugin_by_ip(ipaddr, plugin):
    try:
        if len(ipaddr) < 17:
            rows = db_query("SELECT output, cves, score, state, xrefs from vulns where asset_ip=\"%s\" and plugin_id=%s" % (ipaddr, plugin))
        else:
            rows = db_query("SELECT output, cves, score, state, xrefs from vulns where asset_uuid=\"%s\" and plugin_id=%s" % (ipaddr, plugin))

        for plug in rows:
            click.echo("\nCurrent Plugin State: {} ".format(plug[3]))
            if plug[2] != ' ':
                click.echo("\nVPR Score: {}".format(plug[2]))

            if plug[4] != ' ':
                click.echo("\nCross References\n")
                click.echo("-" * 80)
                for xref in eval(plug[4]):
                    click.echo("Type: {}".format(xref['type']))
                    click.echo("ID: {}".format(xref['id']))
                    click.echo()

            click.echo("\nPlugin Output")
            click.echo("-" * 60)
            click.echo(plug[0])

            if plug[1] != ' ':
                click.echo("CVEs attached to this plugin")
                click.echo("-" * 80)
                click.echo("{}\n".format(plug[1]))
        click.echo()
    except IndexError:
        click.echo("No information found for this plugin")


def vulns_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, severity, state from vulns where asset_uuid='{}' and severity !='info';".format(uuid))

        click.echo("\n{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format("Plugin", "Plugin Name", "Plugin Family", "state", "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            plugin_name = vulns[1]
            plugin_family = vulns[2]
            port = vulns[3]
            protocol = vulns[4]
            severity = vulns[5]
            state = vulns[6]
            click.echo("{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format(plugin_id, textwrap.shorten(plugin_name, 70), textwrap.shorten(plugin_family, 35), state, port, protocol, severity))
        click.echo("")
    except Error as e:
        click.echo(e)


def get_attributes(uuid):
    attr_data = request_data('GET', '/api/v3/assets/{}/attributes'.format(uuid))
    return attr_data


def info_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, severity from vulns where asset_uuid='{}' and severity =='info';".format(uuid))

        click.echo("\n{:10s} {:90s} {:25s} {:6s} {:6s} {}".format("Plugin", "Plugin Name", "Plugin Family", "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            plugin_name = vulns[1]
            plugin_family = vulns[2]
            port = vulns[3]
            protocol = vulns[4]
            severity = vulns[5]
            click.echo("{:10s} {:90s} {:25s} {:6s} {:6s} {}".format(plugin_id, plugin_name, plugin_family, port, protocol, severity))
        click.echo("")
    except Error as e:
        click.echo(e)


def cves_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, cves from vulns where asset_uuid='{}' and cves !=' ';".format(uuid))

        click.echo("\n{:10s} {}".format("Plugin", "CVEs"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            cves = vulns[1]
            click.echo("{:10s} {}".format(plugin_id, textwrap.shorten(cves, 140)))
        click.echo("")
    except IndexError:
        click.echo("Something went wrong")


@click.command(help="Get Asset details based on IP or UUID")
@click.argument('ipaddr')
@click.option('--plugin', default='', help='Find Details on a particular plugin ID')
@click.option('-n', '-netstat', is_flag=True, help='Netstat Established(58561) and Listening and Open Ports(14272)')
@click.option('-p', '-patch', is_flag=True, help='Patch Information - 66334')
@click.option('-t', '-tracert', is_flag=True, help='Trace Route - 10287')
@click.option('-o', '-processes', is_flag=True, help='Process Information - 70329')
@click.option('-c', '-connections', is_flag=True, help='Connection Information - 64582')
@click.option('-s', '-services', is_flag=True, help='Services Running - 22964')
@click.option('-r', '-firewall', is_flag=True, help='Local Firewall Rules - 56310')
@click.option('-patches', is_flag=True, help='Missing Patches - 38153')
@click.option('-d', is_flag=True, help="Scan Detail: 19506 plugin output")
@click.option('-software', is_flag=True, help="Find software installed on Unix(22869) of windows(20811) hosts")
@click.option('-outbound', is_flag=True, help="outbound connections found by nnm")
@click.option('-exploit', is_flag=True, help="Display Solution, Description for each Exploit")
@click.option('-critical', is_flag=True, help="Display Plugin Output for each Critical Vuln")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
@click.option('-vulns', is_flag=True, help="Display all vulnerabilities and their plugin IDs")
@click.option('-info', is_flag=True, help="Display all info plugins and their IDs")
@click.option('-cves', is_flag=True, help="Display all cves found on the asset")
@click.option('-compliance', '-audits', is_flag=True, help="Display all Compliance info for a given asset UUID")
@click.pass_context
def ip(ctx, ipaddr, plugin, n, p, t, o, c, s, r, patches, d, software, outbound, exploit, critical, details, vulns,
       info, cves, compliance):

    if d:
        click.echo('\nScan Detail')
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(19506))

    if n:
        click.echo("\nNetstat info")
        click.echo("Established and Listening")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(58651))
        click.echo("\nNetstat Open Ports")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(14272))

    if p:
        click.echo("\nPatch Information")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(66334))

    if t:
        click.echo("\nTrace Route Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(10287))

    if o:
        click.echo("\nProcess Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(70329))
        plugin_by_ip(ipaddr, str(110483))

    if patches:
        click.echo("\nMissing Patches")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(38153))
        plugin_by_ip(ipaddr, str(66334))

        click.echo("\nLast Reboot")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(56468))

    if c:
        click.echo("\nConnection info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(64582))

    if s:
        try:
            if len(ipaddr) < 17:
                data = db_query("SELECT output, port from vulns where asset_ip=\"%s\" and plugin_id='22964'" % ipaddr)
            else:
                data = db_query("SELECT output, port from vulns where asset_uuid=\"%s\" and plugin_id='22964'" % ipaddr)

            for plugins in data:
                output = plugins[0]
                port = plugins[1]
                click.echo("\n{} {}".format(str(output), str(port)))
            click.echo()
        except IndexError:
            click.echo("No information for plugin 22964")

    if r:
        click.echo("Local Firewall Info")
        click.echo("-" * 15)
        plugin_by_ip(ipaddr, str(56310))
        plugin_by_ip(ipaddr, str(61797))

    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
            click.echo("No Software found")

    if outbound:
        try:
            if len(ipaddr) < 17:
                data = db_query("SELECT output, port, protocol from vulns where asset_ip=\"%s\" and plugin_id='16'" % ipaddr)
            else:
                data = db_query("SELECT output, port, protocol from vulns where asset_uuid=\"%s\" and plugin_id='16'" % ipaddr)

            click.echo("\n{:15s} {:5} {}".format("IP address", "Port", "Protocol"))
            click.echo("-" * 25)
            for plugins in data:
                output = plugins[0]
                port = plugins[1]
                proto = plugins[2]
                click.echo("\n{:15s} {:5} {}".format(str(output), str(port), str(proto)))
            click.echo()
        except Exception as E:
            click.echo("No information for plugin 16")
            click.echo(E)

    if exploit:
        try:
            if len(ipaddr) < 17:
                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                data = set(intial_data)
            else:
                data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

            for assets in data:
                asset_id = assets[0]

                click.echo("\nExploitable Details for : {}\n".format(ipaddr))

                vuln_data = tio.workbenches.asset_vulns(asset_id, ("plugin.attributes.exploit_available", "eq", "true"), age=90)

                for plugins in vuln_data:
                    plugin = plugins['plugin_id']

                    plugin_data = tio.plugins.plugin_details(plugin)

                    click.echo("\n----Exploit Info----")
                    click.echo(plugin_data['name'])
                    click.echo()
                    for attribute in plugin_data['attributes']:

                        if attribute['attribute_name'] == 'cve':
                            cve = attribute['attribute_value']
                            click.echo("CVE ID : " + cve)

                        if attribute['attribute_name'] == 'description':
                            description = attribute['attribute_value']
                            click.echo("Description")
                            click.echo("------------\n")
                            click.echo(description)
                            click.echo()

                        if attribute['attribute_name'] == 'solution':
                            solution = attribute['attribute_value']
                            click.echo("\nSolution")
                            click.echo("------------\n")
                            click.echo(solution)
                            click.echo()
        except Exception as E:
            click.echo(E)

    if critical:
        try:
            if len(ipaddr) < 17:

                intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
                data = set(intial_data)
            else:
                data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

            for assets in data:
                asset_id = assets[0]
                click.echo("\nCritical Vulns for Ip Address : {}\n".format(ipaddr))

                asset_vulns = tio.workbenches.asset_vulns(asset_id, age=90)

                for severities in asset_vulns:
                    vuln_name = severities["plugin_name"]
                    plugin_id = severities["plugin_id"]
                    severity = severities["severity"]
                    state = severities["vulnerability_state"]

                    # only pull the critical vulns; critical = severity 4
                    if severity >= 4:
                        click.echo("Plugin Name : {}".format(vuln_name))
                        click.echo("ID : {}".format(str(plugin_id)))
                        click.echo("Severity : Critical")
                        click.echo("State : {}".format(state))
                        click.echo("----------------\n")
                        plugin_by_ip(str(ipaddr), str(plugin_id))
                        click.echo()
        except Exception as E:
            click.echo(E)

    if details:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))

        for assets in data:
            asset_data = tio.workbenches.asset_info(str(assets[0]))

            try:
                asset_id = asset_data['id']

                click.echo("\nTenable ID")
                click.echo("--------------")
                click.echo(asset_id)

                click.echo("\nNetwork Name")
                click.echo("--------------")
                click.echo(asset_data['network_name'])

                click.echo("\nIdentities")
                click.echo("--------------")
                try:
                    for netbioss in asset_data['netbios_name']:
                        click.echo("Netbios - {}".format(netbioss))
                except KeyError:
                    pass
                try:
                    for fqdns in asset_data['fqdns']:
                        click.echo("FQDN - {}".format(fqdns))
                except KeyError:
                    pass

                try:
                    for hosts in asset_data['hostname']:
                        click.echo("Host Name - {}".format(hosts))
                except KeyError:
                    pass

                try:
                    for agentname in asset_data['agent_name']:
                        click.echo("Agent Name - {}".format(agentname))
                except KeyError:
                    pass

                try:
                    for awsid in asset_data['aws_ec2_instance_id']:
                        click.echo("AWS EC2 Instance ID - {}".format(awsid))
                except KeyError:
                    pass

                try:
                    for awsamiid in asset_data['aws_ec2_ami_id']:
                        click.echo("AWS EC2 AMI ID - {}".format(awsamiid))
                except KeyError:
                    pass

                try:
                    for awsname in asset_data['aws_ec2_name']:
                        click.echo("AWS EC2 Name - {}".format(awsname))
                except KeyError:
                    pass

                click.echo("\nOperating Systems")
                click.echo("--------------")
                try:
                    for oss in asset_data['operating_system']:
                        click.echo(oss)
                except KeyError:
                    pass

                try:
                    click.echo("\nIP Addresses:")
                    click.echo("--------------")
                    for ips in asset_data['ipv4']:
                        click.echo(ips)
                except KeyError:
                    pass

                try:
                    click.echo("\nMac Addresses:")
                    click.echo("--------------")
                    for macs in asset_data['mac_address']:
                        click.echo(macs)
                except KeyError:
                    pass

                try:
                    click.echo("\nCloud Information:")
                    click.echo("--------------")
                    for zone in asset_data['aws_availability_zone']:
                        click.echo("AWS Availability Zone - {}".format(zone))
                except KeyError:
                    pass

                try:
                    for groupname in asset_data['aws_ec2_instance_group_name']:
                        click.echo("AWS Instance group Name - {}".format(groupname))
                except KeyError:
                    pass

                try:
                    for zone in asset_data['aws_availability_zone']:
                        click.echo("AWS Availability Zone - {}".format(zone))
                except KeyError:
                    pass
                try:
                    for statename in asset_data['aws_ec2_instance_state_name']:
                        click.echo("AWS Instance State - {}".format(statename))
                except KeyError:
                    pass
                try:
                    for instatncetype in asset_data['aws_ec2_instance_type']:
                        click.echo("AWS Instance Type - {}".format(instatncetype))
                except KeyError:
                    pass
                try:
                    for region in asset_data['aws_region']:
                        click.echo("AWS Region - {}".format(region))
                except KeyError:
                    pass

                try:
                    for subnet in asset_data['aws_subnet_id']:
                        click.echo("AWS Subnet ID - {}".format(subnet))
                except KeyError:
                    pass
                try:
                    for vpc in asset_data['aws_vpc_id']:
                        click.echo("AWS VPC ID - {}".format(vpc))
                except KeyError:
                    pass
                try:
                    for azureid in asset_data['azure_resource_id']:
                        click.echo("Azure Resource ID - {}".format(azureid))
                except KeyError:
                    pass
                try:
                    for vmid in asset_data['azure_vm_id']:
                        click.echo("Azure VM ID - {}".format(vmid))
                except KeyError:
                    pass

                try:
                    for gcpid in asset_data['gcp_instance_id']:
                        click.echo("GCP Instance ID - {}".format(gcpid))
                except KeyError:
                    pass
                try:
                    for projectid in asset_data['gcp_project_id']:
                        click.echo("GCP Project ID- {}".format(projectid))
                except KeyError:
                    pass
                try:
                    for gcpzone in asset_data['gcp_zone']:
                        click.echo("GCP Zone - {}".format(gcpzone))
                except KeyError:
                    pass
                try:
                    click.echo("\nSources:")
                    click.echo("-" * 15)
                    for source in asset_data['sources']:
                        click.echo(source['name'])
                except KeyError:
                    pass
                try:
                    click.echo("\nTags:")
                    click.echo("-" * 15)
                    for tags in asset_data['tags']:
                        click.echo("{} : {}".format(tags["tag_key"], tags['tag_value']))
                except KeyError:
                    pass
                try:
                    click.echo("\nCustom Attributes:")
                    click.echo("-" * 15)
                    for attr in get_attributes(ipaddr)['attributes']:
                        click.echo("{} : {}".format(attr['name'], attr['value']))

                except KeyError:
                    pass
                click.echo("\nVulnerability Counts")
                click.echo("-" * 15)

                asset_info = tio.workbenches.asset_info(asset_id)

                for vuln in asset_info['counts']['vulnerabilities']['severities']:
                    click.echo("{} : {}".format(vuln["name"], vuln["count"]))

                try:
                    click.echo("\nAsset Exposure Score : {}".format(asset_info['exposure_score']))
                    click.echo("\nAsset Criticality Score : {}".format(asset_info['acr_score']))
                except KeyError:
                    pass

                click.echo("\nLast Authenticated Scan Date - {}".format(asset_data['last_authenticated_scan_date']))
                click.echo("\nLast Licensed Scan Date - {}".format(asset_data['last_licensed_scan_date']))
                click.echo("-" * 50)
                click.echo("-" * 50)
            except KeyError:
                pass

    if vulns:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)
            for assets in data:
                click.echo("\nAsset UUID: {}".format(ipaddr))
                click.echo("Asset IP: {}".format(ipaddr))
                click.echo("-" * 26)
                vulns_by_uuid(assets[0])
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
            click.echo("\nAsset UUID: {}".format(ipaddr))
            click.echo("Asset IP: {}".format(data[0]))
            click.echo("-" * 26)
            vulns_by_uuid(ipaddr)

    if cves:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)

            for assets in data:
                click.echo("\nAsset UUID: {}".format(assets[0]))
                click.echo("Asset IP: {}".format(ipaddr))
                click.echo("-" * 26)
                cves_by_uuid(assets[0])
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
            click.echo("\nAsset UUID: {}".format(ipaddr))
            click.echo("Asset IP: {}".format(data[0]))
            click.echo("-" * 26)
            cves_by_uuid(ipaddr)

    if info:
        if len(ipaddr) < 17:
            intial_data = db_query("SELECT asset_uuid from vulns where asset_ip='{}';".format(ipaddr))
            data = set(intial_data)

            for assets in data:
                click.echo("\nAsset UUID: {}".format(assets[0]))
                click.echo("Asset IP: {}".format(ipaddr))
                click.echo("-" * 26)
                info_by_uuid(assets[0])
        else:
            data = db_query("select uuid from assets where uuid='{}'".format(ipaddr))
            click.echo("\nAsset UUID: {}".format(ipaddr))
            click.echo("Asset IP: {}".format(data[0]))
            click.echo("-" * 26)
            info_by_uuid(ipaddr)

    if plugin != '':
        plugin_by_ip(ipaddr, plugin)

    if compliance:
        if len(ipaddr) > 16:
            compliance_data = db_query("SELECT check_name, status, audit_file from compliance where asset_uuid='{}';".format(ipaddr))
            click.echo("{:84} {:8} {}".format("Check Name", "Status", "Audit File"))
            click.echo("-" * 150)
            for finding in compliance_data:
                check_name = finding[0]
                status = finding[1]
                audit_file = finding[2]
                click.echo("{:85} {:8} {}".format(textwrap.shorten(check_name, width=80), status,
                                                  textwrap.shorten(audit_file, width=60)))
        else:
            click.echo("\nCompliance info requires a UUID\n\nFor simplicity I pulled the UUID(s) with this IP\nPlease re-run your command using one of the below UUIDs")
            uuid_data = db_query("SELECT asset_uuid, asset_hostname from vulns where asset_uuid='{}';".format(ipaddr))

            click.echo("{:45}{}".format("UUID", "FQDN"))
            click.echo("-" * 150)
            for address in uuid_data:
                click.echo("{:45}{}".format(address[0], address[1]))
            click.echo()
