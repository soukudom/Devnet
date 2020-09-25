#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import sys
import json
import urllib3
urllib3.disable_warnings()

# Global static parameters
DNAC = "sandboxdnac.cisco.com" # DNAC address
DNAC_USER = "devnetuser" # DNAC username
DNAC_PASSWORD = "Cisco123!" # DNAC passowrd
DNAC_PORT = 443 # DNAC REST API port
DEBUG = False # Enable or disable debug outputs

# Helper functions
def get_auth_token(controller_ip=DNAC, username=DNAC_USER, password=DNAC_PASSWORD):
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

def create_url(path, controller_ip=DNAC):
    """ Helper function to create a DNAC API endpoint URL
    """

    return "https://%s:%s/api/v1/%s" % (controller_ip, DNAC_PORT, path)

def get_url(url):

    url = create_url(path=url)
    token = get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()

def list_network_devices():
    return get_url("network-device")

def ip_to_id(ip):
    return get_url("network-device/ip-address/%s" % ip)['response']['id']

def get_modules(id):
   return get_url("network-device/module?deviceId=%s" % id)

if __name__ == "__main__":
    # Helper variables
    final = []
    total_sum = {"devices":0,"modules":0,"replaceable":0}
    
    print("Script in progress...")
    # Get and process data from DNAC
    for i in list_network_devices()["response"]:
        if i["hostname"] is None:
            if DEBUG:
                print("Skiping empty hostname...")
            continue
        result = {"hostname":"","modules":0,"fieldreplaceable":0}
        result["hostname"] = i["hostname"]
        dev_id = ip_to_id(i["managementIpAddress"])            
        modules = get_modules(dev_id)
        for j in modules["response"]:
            tmp = j["isFieldReplaceable"]
            if tmp == "TRUE":
                result["modules"] +=1
                result["fieldreplaceable"] +=1
            else:
                result["modules"] +=1
        # Process data based on requirements 
        total_sum["devices"] += 1
        total_sum["modules"] += result["modules"]
        total_sum["replaceable"] += result["fieldreplaceable"]
        final.append(result)            
        if DEBUG:
            print(f'Device {i["hostname"]} successfully processed!')

if DEBUG:
    for i in final:
        print(i)
# Format data into the requestion format
print(f'Answer: {total_sum["devices"]},{total_sum["modules"]},{total_sum["replaceable"]}')
