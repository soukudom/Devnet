import requests
from requests.auth import HTTPBasicAuth
import sys
import json
import urllib3
urllib3.disable_warnings()
import time

# Global static parameters
DNAC = "sandboxdnac.cisco.com" # DNAC address 
DNAC_USER = "devnetuser" # DNAC username 
DNAC_PASSWORD = "Cisco123!" # DNAC passowrd 
DNAC_PORT = 443 # DNAC REST API port 
DEBUG = False # Enable or disable debug outputs
SLEEP = 1 # Waiting period
TRIES = 5 # Number of tries to check if DNAC task is ready to process
TOKEN = None # DNAC API token - no need to define it by user, it is gathered automatically


# Helper functions
def getAuthToken(controller_ip=DNAC, username=DNAC_USER, password=DNAC_PASSWORD):
    """ Authenticates with controller and returns a token to be used in subsequent API invocations
    """

    login_url = "https://{0}:{1}/dna/system/api/v1/auth/token".format(controller_ip, DNAC_PORT)
    result = requests.post(url=login_url, auth=HTTPBasicAuth(DNAC_USER, DNAC_PASSWORD), verify=False)
    result.raise_for_status()

    token = result.json()["Token"]
    return {
        "controller_ip": controller_ip,
        "token": token
    }

def createUrl(path, controller_ip=DNAC):
    """ Helper function to create a DNAC API endpoint URL
    """

    return "https://%s:%s/api/v1/%s" % (controller_ip, DNAC_PORT, path)

def getUrl(url):
    url = createUrl(path=url)
    headers = {'X-auth-token' : TOKEN}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()

def ipToId(ip):
    return getUrl("network-device/ip-address/%s" % ip)['response']['id']

def getAllDevicesIds():
    network_devices = getUrl("network-device")
    dev_ids = []
    for i in network_devices["response"]:
        dev_id = ipToId(i["managementIpAddress"])
        dev_ids.append("\""+dev_id+"\"")
    if DEBUG:
        print("Available device ids:",dev_ids)
    return ",".join(dev_ids)

def sendCommandToAllDevices(dev_ids):
    url = "https://sandboxdnac.cisco.com:443/api/v1/network-device-poller/cli/read-request"
    token = getAuthToken()
    headers = {'X-auth-token' : token['token'],'Content-Type': 'application/json'}
    payload = '{\"name\" : \"show ntp\", \"commands\" : [\"show ntp status\"], \"deviceUuids\" : ['+dev_ids+']}'
    response = requests.request("POST", url, headers=headers, data = payload, verify = False)
    result = json.loads(response.text.encode("utf8"))
    taskId = result["response"]
    return taskId

def processTaskResult(task_result):
    device_num = 1
    for i in task_result:
        print(f"===== BEGIN DEVICE {device_num} =====")
        print(i["commandResponses"]["SUCCESS"]["show ntp status"])
        print(f"===== END DEVICE {device_num} =====")
        device_num += 1

def getTaskStatus(task_id):
    global SLEEP
    global TRIES
    if DEBUG:
        print("Task ID is:",task_id)
    while TRIES:
        if DEBUG:
            print("Checking task.. Sleep interval:",SLEEP,"Remaining tries:",TRIES)
        time.sleep(SLEEP)
        task_status = getUrl("task/"+task_id["taskId"])
        if task_status["response"]["isError"] == "True":
            print("Error in running device command")
        try:
            task_status["response"]["endTime"]
            if DEBUG:
                print("Task is finished")
            break
        except Exception:
            if DEBUG:
                print("Task is still running continue..")
        if DEBUG:
            print("Info data about the task:",task_status)

        SLEEP += 1
        TRIES -= 1

    fileId = task_status["response"]["progress"].split(":")[1][:-1].strip('"')
    return fileId

def getTaskResult(file_id):
    task_result = getUrl("file/"+file_id)
    if DEBUG:
        print("Result data from the task:",task_result)
    processTaskResult(task_result)

if __name__ == "__main__":
    print("Script in progress...")
    TOKEN = getAuthToken()["token"]
    dev_ids = getAllDevicesIds()
    task_id = sendCommandToAllDevices(dev_ids)
    file_id = getTaskStatus(task_id)
    getTaskResult(file_id)

