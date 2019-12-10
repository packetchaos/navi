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
            except Error:
                pass

    except IndexError:
        print("No information found for this plugin")
    except Exception as e:
        print(e)



@click.command(help="Get IP specfic information")
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
        print("Test")
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
                cur.execute("SELECT * from vulns where plugin_id='22964';")

                data = cur.fetchall()

                for plugins in data:
                    web = plugins[6]  # output
                    wsplit = web.split("\n")

                    server = wsplit[0]
                    port = plugins[10]  # port number
                    proto = plugins[11]  # Portocol
                    asset = plugins[1]  # Ip address

                    print(asset, ": Has a Web Server Running :")
                    print(server, "is running on: ", port, "/", proto)
                    print()
        except Error as e:
            print("No information for plugin 22964", e)

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
                cur.execute("SELECT * from vulns where plugin_id='16';")

                data = cur.fetchall()
                print("IP Address", " - ", "Port", " - ", "Protocol")
                print("-------------------------------")
                for plugins in data:
                    web = plugins[6]  # output
                    wsplit = web.split("\n")

                    server = wsplit[0]
                    port = plugins[10]  # port number
                    proto = plugins[11]  # Portocol
                    asset = plugins[1]  # Ip address
                    print(asset, " - ", port, "  - ", proto + "\n")
        except Error as e:
            print("No information for plugin 16", e)

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
        except Error as e:
            print("No Exploit Details found for: ", ipaddr, e)

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
        except Error as e:
            print("No Critical Vulnerabilities found for : ", ipaddr, e)

    if details:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")
            data = cur.fetchall()
            for assets in data:
                asset_data = request_data('GET', '/workbenches/assets/'+ assets[0] + '/info')
                try:
                    asset_id = asset_data['info']['id']

                    print("\nTenable ID")
                    print("--------------")
                    print(asset_id)

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
                        except KeyError:
                            pass
                    except KeyError:
                        print("Check your API keys or your internet connection")

                    print("\nLast Authenticated Scan Date - ", asset_data['info']['last_authenticated_scan_date'])

                except KeyError:
                    pass
