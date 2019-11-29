import csv
from .api_wrapper import request_data


def consec_export():
    data = request_data('GET', '/container-security/api/v2/images?limit=1000')
    with open('consec_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Container Name", "Docker ID", "# of Vulns"]
        agent_writer.writerow(header_list)

        for images in data["items"]:
            name = images["name"]
            docker_id = images["imageHash"]
            vulns = images["numberOfVulns"]
            agent_writer.writerow([name, docker_id, vulns])
