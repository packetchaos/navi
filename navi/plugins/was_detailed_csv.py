import csv
from .api_wrapper import request_data


def was_detailed_export():
    # Crete a csv file object
    with open('was_detailed_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        # write our Header information first
        header_list = ["Scan Name", "APP", "Risk", "Plugin ID", "Plugin Name", "Description", "Solution", "See Also",
                       "CVSS", "CVSS3", "CVEs", "CWE", "WASC", "OWASP", "Scan Finalized Date"]
        agent_writer.writerow(header_list)

        params = {"size": "1000"}
        # Grab all of the Scans
        data = request_data('GET', '/was/v2/scans', params=params)

        for scan_data in data['data']:
            was_scan_id = scan_data['scan_id']
            status = scan_data['status']

            # Ignore all scans that have not completed
            if status == 'completed':
                report = request_data('GET', '/was/v2/scans/' + was_scan_id + '/report')

                try:
                    name = report['config']['name']
                    finalized = report['scan']['finalized_at']
                    try:
                        target = report['scan']['target']
                    except KeyError:
                        target = report['config']['settings']['target']

                    for finding in report['findings']:
                        csv_list = []
                        owasp_list = []
                        description = finding['description']
                        try:
                            solution = finding['solution']
                        except KeyError:
                            solution = ''
                        try:
                            see_also = finding['see_also']
                        except KeyError:
                            see_also = ''

                        risk = finding['risk_factor']

                        try:
                            cvss = finding['cvss']
                        except KeyError:
                            cvss = ''
                        try:
                            cvss3 = finding['cvssv3']
                        except KeyError:
                            cvss3 = ''

                        cves = finding['cves']
                        try:
                            cwe = finding['cwe']
                        except KeyError:
                            cwe = ''

                        try:
                            wasc = finding['wasc']
                        except KeyError:
                            wasc = ''

                        # Grab multiples values here
                        for owasp in finding['owasp']:
                            if owasp['year'] == '2017':
                                owasp_list.append(owasp['category'])

                        # ignore info vulns
                        if risk != "info":
                            plugin_id = finding['plugin_id']
                            plugin_name = finding['name']

                            csv_list.append(name)
                            csv_list.append(target)
                            csv_list.append(risk)
                            csv_list.append(plugin_id)
                            csv_list.append(plugin_name)
                            csv_list.append(description)
                            csv_list.append(solution)
                            csv_list.append(see_also)
                            csv_list.append(cvss)
                            csv_list.append(cvss3)
                            csv_list.append(cves)
                            csv_list.append(cwe)
                            csv_list.append(wasc)
                            csv_list.append(owasp_list)
                            csv_list.append(finalized)

                            agent_writer.writerow(csv_list)
                except TypeError:
                    pass
        print()
