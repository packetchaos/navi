import click
import time
from .api_wrapper import request_data
from .scan_details import scan_details
from .error_msg import error_msg


@click.command(help="Get the Latest Scan information")
@click.option('-latest', is_flag=True, help="Report the Last Scan Details")
@click.option('--container', default='', help='Report CVSS 7 or above by \'/repository/image/tag\'')
@click.option('--docker', default='', help='Report CVSS 7 or above by Docker ID')
@click.option('--comply', default='', help='Check to see if your container complies with your Corporate Policy')
@click.option('--details', default='', help='Report Scan Details including Vulnerability Counts by Scan ID')
@click.option('--summary', default='', help="Report Scan Summary information by Scan ID")
def report(latest, container, docker, comply, details, summary):
    # get the latest Scan Details
    if latest:
        try:
            data = request_data('GET', '/scans')
            l = []
            e = {}
            for x in data["scans"]:
                # keep UUID and Time together
                # get last modication date for duration computation
                epoch_time = x["last_modification_date"]
                # get the scanner ID to display the name of the scanner
                d = x["id"]
                # need to identify type to compare against pvs and agent scans
                scan_type = str(x["type"])
                # don't capture the PVS or Agent data in latest
                while scan_type not in ['pvs', 'agent', 'webapp', 'lce']:
                    # put scans in a list to find the latest
                    l.append(epoch_time)
                    # put the time and id into a dictionary
                    e[epoch_time] = d
                    break

            # find the latest time
            grab_time = max(l)

            # get the scan with the corresponding ID
            grab_uuid = e[grab_time]

            # turn epoch time into something readable
            epock_latest = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(grab_time))
            print("\nThe last Scan run was at " + epock_latest)
            scan_details(str(grab_uuid))
        except Exception as E:
            error_msg(E)

    if container:
        try:
            data = request_data('GET', '/container-security/api/v2/reports' + str(container))
            try:
                for vulns in data['findings']:
                    if float(vulns['nvdFinding']['cvss_score']) >= 7:
                        print("CVE ID :", vulns['nvdFinding']['cve'])
                        print("CVSS Score : ", vulns['nvdFinding']['cvss_score'])
                        print("----------------------")
                        print("\nDescription : \n\n", vulns['nvdFinding']['description'])
                        print("\nRemediation : \n\n", vulns['nvdFinding']['remediation'])
                        print("----------------------END-------------------------\n")
            except TypeError:
                print("This Container has no data or is not found")
            except ValueError:
                pass
        except Exception as E:
            error_msg(E)

    if docker:
        try:
            data = request_data('GET', '/container-security/api/v1/reports/by_image?image_id=' + str(docker))

            try:
                for vulns in data['findings']:
                    if float(vulns['nvdFinding']['cvss_score']) >= 7:
                        print("CVE ID :", vulns['nvdFinding']['cve'])
                        print("CVSS Score : ", vulns['nvdFinding']['cvss_score'])
                        print("-----------------------")
                        print("\nDescription \n\n: ", vulns['nvdFinding']['description'])
                        print("\nRemediation : \n\n", vulns['nvdFinding']['remediation'])
                        print("----------------------END-------------------------\n")
            except TypeError:
                print("This Container has no data or is not found")
            except ValueError:
                pass
        except Exception as E:
            error_msg(E)

    if comply:
        try:
            data = request_data('GET', '/container-security/api/v1/policycompliance?image_id=' + str(comply))

            print("Status : ", data['status'])
        except Exception as E:
            error_msg(E)

    if details:
        try:
            data = request_data('GET', '/scans/' + str(details))
            try:
                print()
                print("Scan Details for Scan ID : "+details)
                print()
                print("Notes: \b")
                try:
                    print(data['notes'][0]['message'])
                except KeyError:
                    pass
                print()
                print("Vulnerability Counts")
                print("--------------------")
                print("Critical : ", data['hosts'][0]['critical'])
                print("high : ", data['hosts'][0]['high'])
                print("medium : ", data['hosts'][0]['medium'])
                print("low : ", data['hosts'][0]['low'])
                try:
                    print("--------------")
                    print("Score : ", data['hosts'][0]['score'])
                except KeyError:
                    pass
                print()
                print("Vulnerability Details")
                print("---------------------")

                for vulns in data['vulnerabilities']:
                    if vulns['severity'] != 0:
                        print(vulns['plugin_name'], " : ", vulns['count'])
            except:
                print("Check the scan ID")
        except Exception as E:
            error_msg(E)

    if summary:
        try:
            print("\nHere is the Summary of your Scan :")
            print("----------------------------------")
            scan_details(str(summary))
        except Exception as E:
            error_msg(E)
