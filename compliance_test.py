import requests


def grab_headers():
    access_key = '697cbb12a358606c673c95ccd8c8a8b23a2c7fe6cdfbc8804ce45714cbeaad1e'
    secret_key = '7457773f3d09c94e9c34308e8da54be9247f220f8ed8bcda59b6c17507ca3536'
    return {'Content-type': 'application/json', 'user-agent': 'Casey Reid', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_export():
    payload = {"num_findings": 500}
    data = requests.request("POST", "HTTPS://cloud.tenable.com/compliance/export", headers=grab_headers(), json=payload, verify=True)

    print(data.json())


def check_export():
    data = requests.request("GET", "HTTPS://cloud.tenable.com/compliance/export/5872dc40-d6b9-4cc6-8df4-cabf5b9ffbf3/status", headers=grab_headers(), verify=True)

    print(data.json())

#request_export()

check_export()
