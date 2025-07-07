#!/usr/bin/python3

# Script: updateMDMServer.py
# Karthikeyan Marappan
#
# Purpose
# Assign or Unassign Devices to a Device Management Service (https://developer.apple.com/documentation/appleschoolmanagerapi/create-an-orgdeviceactivity)
# CSV will be downloaded if there is  failure in updating the MDM Server. This CSV will be same as you will download from ABM/ASM portal activity
# It follows Apple’s JWT-based OAuth flow documented here: https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api
#
# Replace the placeholder values below (`Certificate.pem`, client_id, device_ids_file etc.) with your own ABM credentials. (https://support.apple.com/en-ca/guide/apple-school-manager/axm33189f66a/1/web/1)
#
# CLIENT_ASSERTION_VALIDITY_DAYS #Validity of assertion and Apple support max of 180 days


import os
import json
import time
import uuid
import requests
import sys, re
import csv
import datetime as dt
from authlib.jose import jwt
from Crypto.PublicKey import ECC

# --------------------------------------------------------------------
# Apple school Manager OAuth configuration
# --------------------------------------------------------------------
private_key_file      = "Certificate.pem"                  # path of EC private key (.pem)
client_assertion_file = "client_assertion.json"            # cache for JWT + expiry
client_id             = "SCHOOLAPI.rstuvw-1f50-efgh-abcd-ijklmnop"
team_id               = "SCHOOLAPI.rstuvw-1f50-efgh-abcd-ijklmnop"
key_id                = "be678907667-888h-40ec-abcd-9m8n7b6v"
audience              = "https://account.apple.com/auth/oauth2/v2/token"
jwt_alg               = "ES256"
scope                 = "school.api"
serialNumberList        = "serialnumbers.txt"                               # path of serial number list

# MDM server ID to assign devices to
MDM_SERVER_ID = "B996DAAAA4295AFF799203AAAA8FEA"  # Replace with your MDM server ID. You can use List Device Management Services API or get it from ABM/ASM. 
activity_type = "ASSIGN_DEVICES"                  # ASSIGN_DEVICES or UNASSIGN_DEVICES 

# --------------------------------------------------------------------
# How long (in days) the next JWT should stay valid.
# --------------------------------------------------------------------
CLIENT_ASSERTION_VALIDITY_DAYS = 1

# validate and clamp to Apple’s limits
if CLIENT_ASSERTION_VALIDITY_DAYS > 180:
    print(f"Requested {CLIENT_ASSERTION_VALIDITY_DAYS} days – Apple allows max 180, using 180 instead.")
    CLIENT_ASSERTION_VALIDITY_DAYS = 180
elif CLIENT_ASSERTION_VALIDITY_DAYS < 1:
    print(f"Requested {CLIENT_ASSERTION_VALIDITY_DAYS} days – must be at least 1, using 1 instead.")
    CLIENT_ASSERTION_VALIDITY_DAYS = 1
    
# --------------------------------------------------------------------
# Read device IDs from a file
# --------------------------------------------------------------------
def read_device_ids_from_txt(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines() if line.strip()]
    
# --------------------------------------------------------------------
# Load existing assertion if valid
# --------------------------------------------------------------------
def load_valid_client_assertion():
    if not os.path.exists(client_assertion_file):
        return None
    try:
        with open(client_assertion_file, "r") as f:
            cached = json.load(f)
        exp = int(cached.get("exp", 0))                  # expiry (epoch seconds)
        now = int(dt.datetime.utcnow().timestamp())      # current time (UTC)
        if exp > now + 60:
            remaining_days = (exp - now) // 86_400
            print(f"Using cached client assertion (≈ {remaining_days} days remaining).")
            return cached["client_assertion"]
    except Exception:
        pass
    return None

# --------------------------------------------------------------------
# Generate new assertion and cache it
# --------------------------------------------------------------------
def generate_client_assertion():
    issued = int(dt.datetime.utcnow().timestamp())
    exp    = issued + 86400 * CLIENT_ASSERTION_VALIDITY_DAYS
    header = {"alg": jwt_alg, "kid": key_id}
    payload = {
        "sub": client_id,
        "aud": audience,
        "iat": issued,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "iss": team_id
    }
    with open(private_key_file, "r") as f:
        priv_key = ECC.import_key(f.read())
    assertion = jwt.encode(header=header, payload=payload, key=priv_key.export_key(format="PEM")).decode("utf-8")
    with open(client_assertion_file, "w") as f:
        json.dump({"client_assertion": assertion, "exp": exp}, f)
    print("Generated new client assertion.")
    return assertion

# --------------------------------------------------------------------
# Request access token with a given client_assertion
# --------------------------------------------------------------------
def request_access_token(assertion):
    response = requests.post(
        "https://account.apple.com/auth/oauth2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "scope": scope
        },
        timeout=30
    )
    return response

# --------------------------------------------------------------------
# Assign devices to MDM server
# --------------------------------------------------------------------
def assign_devices_to_mdm_server(device_ids, mdm_server_id, access_token, activity_type):
    url = "https://api-school.apple.com/v1/orgDeviceActivities"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    data = {
        "data": {
            "type": "orgDeviceActivities",
            "attributes": {"activityType": activity_type},
            "relationships": {
                "mdmServer": {
                    "data": {"type": "mdmServers", "id": mdm_server_id}
                },
                "devices": {
                    "data": [{"type": "orgDevices", "id": device_id} for device_id in device_ids]
                }
            }
        }
    }
    
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        result = response.json()
        activity_id = result["data"]["id"]
        print(f"Activity ID: {activity_id}")
        time.sleep(30)
        check_activity_status(activity_id, access_token)
    else:
        print(f"Error during {activity_type}: {response.status_code}, {response.text}")
        sys.exit(1)
        
        
def check_activity_status(activity_id, access_token):
    url = f"https://api-school.apple.com/v1/orgDeviceActivities/{activity_id}"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    params = {
        "fields[orgDeviceActivities]": "status,subStatus,createdDateTime,completedDateTime,downloadUrl"
    }
    
    # Optional: Wait a few seconds to give the activity time to complete
    print(f"Checking status for activity {activity_id}...")
    time.sleep(5)
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json().get("data", {})
        attrs = data.get("attributes", {})
        sub_status = attrs.get("subStatus")
        status = attrs.get("status")
        print(f"Status: {status}, SubStatus: {sub_status}")
        
        if sub_status == "COMPLETED_WITH_SUCCESS":
            print("All devices were successfully processed.")
        else:
            download_url = attrs.get("downloadUrl")
            if download_url:
                print("Some devices failed. Downloading log file...")
                download_activity_log(download_url)
            else:
                print("Operation failed, and no log file was provided.")
    else:
        print(f"Failed to fetch activity status: {response.status_code}")
        sys.exit(1)
        
def download_activity_log(download_url):
    response = requests.get(download_url, allow_redirects=True)
    if response.status_code == 200:
        # Format timestamp
        timestamp = datetime.datetime.now().strftime("%d%m%y%H%M%S")
        # Extract filename from Content-Disposition header
        content_disp = response.headers.get("Content-Disposition", "")
        match = re.search(r'filename="(.+?)"', content_disp)
        if match:
            original_filename = match.group(1)
            base, ext = os.path.splitext(original_filename)
            filename = f"{base}_{timestamp}{ext}"
        else:
            filename = f"activity_log_{timestamp}.csv"
            
        with open(filename, "wb") as f:
            f.write(response.content)
        print(f"📄 Log file downloaded: {filename}")
    else:
        print(f"❌ Failed to download log file: {response.status_code}")
        
# --------------------------------------------------------------------
# Main Execution Flow
# --------------------------------------------------------------------
        
# Try cached or generate a client assertion
client_assertion = load_valid_client_assertion() or generate_client_assertion()

# First attempt to get access token
token_resp = request_access_token(client_assertion) #Uncomment when not caching

# If token failed due to invalid client, regenerate and try again
if token_resp.status_code != 200 and "invalid_client" in token_resp.text:
    print("Access token failed: invalid_client. Regenerating client assertion and retrying...")
    client_assertion = generate_client_assertion()
    token_resp = request_access_token(client_assertion)
    
# Final check
if token_resp.status_code != 200:
    print(f"Access-token request failed {token_resp.status_code}: {token_resp.text}")
    raise SystemExit("Access token request failed after retry. Please verify your Apple Business Manager credentials.")
    
access_token = token_resp.json()["access_token"]
print("Fetched access token successfully.")

# Read device IDs and assign them
device_ids = read_device_ids_from_txt(serialNumberList)
assign_devices_to_mdm_server(device_ids, MDM_SERVER_ID, access_token, activity_type)
