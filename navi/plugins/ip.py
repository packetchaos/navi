import click
from sqlite3 import Error
from .api_wrapper import request_data
from .database import new_db_connection


def plugin_by_ip(ipaddr, plugin):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT output from vulns where asset_ip=\"%s\" and plugin_id=%s" % (ipaddr, plugin))
                rows = cur.fetchall()
                print(rows[0][0])
            except:
                pass

    except Error as e:
        print(e)

    except IndexError:
        print("No information found for this plugin")


@click.command(help="Get IP specific information")
@click.argument('ipaddr')
@click.option('--plugin', default='', help='Find Details on a particular plugin ID')
@click.option('-n', is_flag=True, help='Netstat Established(58561) and Listening and Open Ports(14272)')
@click.option('-p', is_flag=True, help='Patch Information - 66334')
@click.option('-t', is_flag=True, help='Trace Route - 10287')
@click.option('-o', is_flag=True, help='Process Information - 70329')
@click.option('-c', is_flag=True, help='Connection Information - 64582')
@click.option('-s', is_flag=True, help='Services Running - 22964')
@click.option('-r', is_flag=True, help='Local Firewall Rules - 56310')
@click.option('-patches', is_flag=True, help='Missing Patches - 38153')
@click.option('-d', is_flag=True, help="Scan Detail: 19506 plugin output")
@click.option('-software', is_flag=True, help="Find software installed on Unix(22869) of windows(20811) hosts")
@click.option('-outbound', is_flag=True, help="outbound connections found by nnm")
@click.option('-exploit', is_flag=True, help="Display exploitable vulnerabilities")
@click.option('-critical', is_flag=True, help="Display critical vulnerabilities")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
@click.pass_context
def ip(ctx, ipaddr, plugin, n, p, t, o, c, s, r, patches, d, software, outbound, exploit, critical, details):
    plugin_by_ip(ipaddr, plugin)

    if d:
        click.echo('\nScan Detail')
        click.echo('----------------\n')
        plugin_by_ip(ipaddr, str(19506))

    if n:
        click.echo("\nNetstat info")
        click.echo("Established and Listening")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(58651))
        click.echo("\nNetstat Open Ports")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(14272))

    if p:
        click.echo("\nPatch Information")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(66334))

    if t:
        click.echo("\nTrace Route Info")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(10287))

    if o:
        click.echo("\nProcess Info")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(70329))
        plugin_by_ip(ipaddr, str(110483))

    if patches:
        click.echo("\nMissing Patches")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(38153))
        plugin_by_ip(ipaddr, str(66334))

        click.echo("\nLast Reboot")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(56468))

    if c:
        click.echo("\nConnection info")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(64582))

    if s:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT output, port from vulns where asset_ip=\"%s\" and plugin_id='22964'" % ipaddr)
                data = cur.fetchall()

                for plugins in data:
                    print("\n", plugins[0], plugins[1])
                print()
        except IndexError:
            print("No information for plugin 22964")

    if r:
        click.echo("Local Firewall Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(56310))
        plugin_by_ip(ipaddr, str(61797))

    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
            print("No Software found")

    if outbound:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT output, port, protocol from vulns where asset_ip=\"%s\" and plugin_id='16'" % ipaddr)

                data = cur.fetchall()
                print("\nIP Address", " - ", "Port", " - ", "Protocol")
                print("-------------------------------")
                for plugins in data:
                    print("\n", plugins[0].ljust(13), plugins[1].ljust(10), plugins[2])
                print()
        except:
            print("No information for plugin 16")

    if exploit:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")

                data = cur.fetchall()
                for assets in data:

                    asset_id = assets[0]

                    print("Exploitable Details for : " + ipaddr)
                    print()
                    V = request_data('GET', '/workbenches/assets/' + asset_id + '/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')

                    for plugins in range(len(V['vulnerabilities'])):
                        plugin = V['vulnerabilities'][plugins]['plugin_id']

                        P = request_data('GET', '/plugins/plugin/' + str(plugin))
                        # pprint.pprint(P['attributes'])
                        print("\n----Exploit Info----")
                        print(P['name'])
                        print()
                        for attribute in range(len(P['attributes'])):

                            if P['attributes'][attribute]['attribute_name'] == 'cve':
                                cve = P['attributes'][attribute]['attribute_value']
                                print("CVE ID : " + cve)

                            if P['attributes'][attribute]['attribute_name'] == 'description':
                                description = P['attributes'][attribute]['attribute_value']
                                print("Description")
                                print("------------\n")
                                print(description)
                                print()

                            if P['attributes'][attribute]['attribute_name'] == 'solution':
                                solution = P['attributes'][attribute]['attribute_value']
                                print("\nSolution")
                                print("------------\n")
                                print(solution)
                                print()
        except:
            print("No Exploit Details found for: ", ipaddr)

    if critical:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")

                data = cur.fetchall()
                for assets in data:
                    asset_id = assets[0]
                    print("Critical Vulns for Ip Address :" + ipaddr + "\n")
                    vulns = request_data('GET',
                                         "/workbenches/assets/"
                                         + asset_id + "/vulnerabilities?date_range=90")
                    for severities in range(len(vulns["vulnerabilities"])):
                        vuln_name = vulns["vulnerabilities"][severities]["plugin_name"]
                        plugin_id = vulns["vulnerabilities"][severities]["plugin_id"]
                        severity = vulns["vulnerabilities"][severities]["severity"]
                        state = vulns["vulnerabilities"][severities]["vulnerability_state"]

                        # only pull the critical vulns; critical = severity 4
                        if severity >= 4:
                            print("Plugin Name : " + vuln_name)
                            print("ID : " + str(plugin_id))
                            print("Severity : Critical")
                            print("State : " + state)
                            print("----------------\n")
                            plugin_by_ip(str(ipaddr), str(plugin_id))
                            print()
        except:
            print("No Critical Vulnerabilities found for : ", ipaddr)

    if details:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")

            data = cur.fetchall()
            for assets in data:
                asset_data = request_data('GET', '/workbenches/assets/' + assets[0] + '/info?date_range=90')

                try:
                    asset_id = asset_data['info']['id']

                    print("\nTenable ID")
                    print("--------------")
                    print(asset_id)

                    print("\nNetwork Name")
                    print("--------------")
                    print(asset_data['info']['network_name'])

                    print("\nIdentities")
                    print("--------------")
                    try:
                        for netbioss in asset_data['info']['netbios_name']:
                            print("Netbios - ", netbioss)
                    except KeyError:
                        pass
                    try:
                        for fqdns in asset_data['info']['fqdns']:
                            print("FQDN - ", fqdns)
                    except KeyError:
                        pass

                    try:
                        for hosts in asset_data['info']['hostname']:
                            print("Host Name -", hosts)
                    except KeyError:
                        pass

                    try:
                        for agentname in asset_data['info']['agent_name']:
                            print("Agent Name -", agentname)
                    except KeyError:
                        pass

                    try:
                        for awsid in asset_data['info']['aws_ec2_instance_id']:
                            print("AWS EC2 Instance ID - ", awsid)
                    except KeyError:
                        pass

                    try:
                        for awsamiid in asset_data['info']['aws_ec2_ami_id']:
                            print("AWS EC2 AMI ID - ", awsamiid)
                    except KeyError:
                        pass

                    try:
                        for awsname in asset_data['info']['aws_ec2_name']:
                            print("AWS EC2 Name - ", awsname)
                    except KeyError:
                        pass

                    print("\nOperating Systems")
                    print("--------------")
                    try:
                        for oss in asset_data['info']['operating_system']:
                            print(oss)
                    except KeyError:
                        pass

                    try:
                        print("\nIP Addresses:")
                        print("--------------")
                        for ips in asset_data['info']['ipv4']:
                            print(ips)
                    except KeyError:
                        pass

                    try:
                        print("\nMac Addresses:")
                        print("--------------")
                        for macs in asset_data['info']['mac_address']:
                            print(macs)
                    except KeyError:
                        pass

                    try:
                        print("\nCloud Information:")
                        print("--------------")
                        for zone in asset_data['info']['aws_availability_zone']:
                            print("AWS Availability Zone - ", zone)
                    except KeyError:
                        pass

                    try:
                        for groupname in asset_data['info']['aws_ec2_instance_group_name']:
                            print("AWS Instance group Name - ", groupname)
                    except KeyError:
                        pass

                    try:
                        for zone in asset_data['info']['aws_availability_zone']:
                            print("AWS Availability Zone - ", zone)
                    except KeyError:
                        pass
                    try:
                        for statename in asset_data['info']['aws_ec2_instance_state_name']:
                            print("AWS Instance State - ", statename)
                    except KeyError:
                        pass
                    try:
                        for instatncetype in asset_data['info']['aws_ec2_instance_type']:
                            print("AWS Instance Type - ", instatncetype)
                    except KeyError:
                        pass
                    try:
                        for region in asset_data['info']['aws_region']:
                            print("AWS Region - ", region)
                    except KeyError:
                        pass

                    try:
                        for subnet in asset_data['info']['aws_subnet_id']:
                            print("AWS Subnet ID - ", subnet)
                    except KeyError:
                        pass
                    try:
                        for vpc in asset_data['info']['aws_vpc_id']:
                            print("AWS VPC ID - ", vpc)
                    except KeyError:
                        pass
                    try:
                        for azureid in asset_data['info']['azure_resource_id']:
                            print("Azure Resource ID - ", azureid)
                    except KeyError:
                        pass
                    try:
                        for vmid in asset_data['info']['azure_vm_id']:
                            print("Azure VM ID - ", vmid)
                    except KeyError:
                        pass

                    try:
                        for gcpid in asset_data['info']['gcp_instance_id']:
                            print("GCP Instance ID - ", gcpid)
                    except KeyError:
                        pass
                    try:
                        for projectid in asset_data['info']['gcp_project_id']:
                            print("GCP Project ID- ", projectid)
                    except KeyError:
                        pass
                    try:
                        for gcpzone in asset_data['info']['gcp_zone']:
                            print("GCP Zone - ", gcpzone)
                    except KeyError:
                        pass
                    try:
                        print("\nSources:")
                        print("--------------")
                        for source in asset_data['info']['sources']:
                            print(source['name'])
                    except KeyError:
                        pass
                    try:
                        print("\nTags:")
                        print("--------------")
                        for tags in asset_data['info']['tags']:
                            print(tags["tag_key"], ':', tags['tag_value'])
                    except KeyError:
                        pass

                    try:
                        print("\nVulnerability Counts")
                        print("--------------")
                        asset_info = request_data('GET', '/workbenches/assets/' + asset_id + '/info')

                        for vuln in asset_info['info']['counts']['vulnerabilities']['severities']:
                            print(vuln["name"], " : ", vuln["count"])

                        try:
                            print("\nAsset Exposure Score : ", asset_info['info']['exposure_score'])
                            print("\nAsset Criticality Score :", asset_info['info']['acr_score'])
                        except:
                            pass

                    except:
                        print("Check your API keys or your internet connection")

                    print("\nLast Authenticated Scan Date - ", asset_data['info']['last_authenticated_scan_date'])
                    print("-" * 50)
                    print("-" * 50)
                except:
                    pass
