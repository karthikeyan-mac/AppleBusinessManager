#!/usr/bin/python3
"""
Script: fetch_assigned_servers.py
Purpose
-------
Query Apple school Manager (ABM) for the **assigned server** information of a list of device
resource IDs.  
https://developer.apple.com/documentation/appleschoolmanagerapi/get-the-assigned-server-information-for-an-orgdevice
It follows Apple’s JWT-based OAuth flow documented here:
https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api

Key points
----------
1. Generates (or re-uses) a `client_assertion` JWT signed with your EC private key.
2. Exchanges that assertion for an **access token** (`scope = school.api`).
3. Calls the **assignedServer** endpoint  
	`GET /v1/orgDevices/{id}/assignedServer`  
	which returns server attributes (`serverName`, `serverType`, timestamps).
4. Writes a CSV (`device_assigned_servers.csv`) containing:
	device_id, server_id, server_type, serverName, serverType,
	createdDateTime, updatedDateTime.
5. Prints a summary of how many look-ups succeeded and how many failed / not found.

Replace the placeholder values below (`Certificate.pem`, client_id, device_ids_file etc.) 
with your own ABM credentials.
https://support.apple.com/en-ca/guide/apple-school-manager/axm33189f66a/1/web/1
Add the serial number list text file path to serialNumberList varibale
"""

import os
import json
import time
import uuid
import csv
import requests
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
serialNumberList      = "serialnumbers.txt" # path of serial number list

# --------------------------------------------------------------------
# Function to read device IDs from a text file
# --------------------------------------------------------------------
def read_device_ids_from_txt(file_path):
    with open(file_path, 'r') as file:
        device_ids = [line.strip() for line in file.readlines()]
    return device_ids

# Or read device IDs from a text file:
device_ids = read_device_ids_from_txt(serialNumberList)

# --------------------------------------------------------------------
# Helper: reuse client_assertion if still valid (> 90 days left)
# --------------------------------------------------------------------
def load_valid_client_assertion() -> str | None:
    if not os.path.exists(client_assertion_file):
        return None
    try:
        with open(client_assertion_file, "r") as f:
            data = json.load(f)
        exp  = int(data.get("exp", 0))
        now  = int(dt.datetime.utcnow().timestamp())
        days = (exp - now) // 86400
        if days > 90:
            print(f"Using cached client assertion (valid {days} days).")
            return data["client_assertion"]
    except Exception:
        pass
    return None

# --------------------------------------------------------------------
# Helper: generate and cache a new client_assertion (valid 180 days)
# --------------------------------------------------------------------
def generate_client_assertion() -> str:
    issued = int(dt.datetime.utcnow().timestamp())
    exp    = issued + 86400 * 180                       # 180 days
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
    assertion = jwt.encode(header=header,
                            payload=payload,
                            key=priv_key.export_key(format="PEM")).decode("utf-8")
    with open(client_assertion_file, "w") as f:
        json.dump({"client_assertion": assertion, "exp": exp}, f)
    print("Generated new client assertion.")
    return assertion

client_assertion = load_valid_client_assertion() or generate_client_assertion()

# --------------------------------------------------------------------
# Exchange client_assertion for ABM access token
# --------------------------------------------------------------------
token_resp = requests.post(
    "https://account.apple.com/auth/oauth2/token",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
        "scope": scope
    },
    timeout=30
)
if token_resp.status_code != 200:
    raise SystemExit(f"Access-token request failed {token_resp.status_code}: {token_resp.text}")
access_token = token_resp.json()["access_token"]
print("Fetched access token.")

# --------------------------------------------------------------------
# Query assignedServer for each device
# --------------------------------------------------------------------
base_url      = "https://api-school.apple.com/v1/orgDevices"
headers_auth  = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
csv_rows      = []
found, failed = 0, 0

for device_id in device_ids:
    url = f"{base_url}/{device_id}/assignedServer"   # full resource incl. attributes
    resp = requests.get(url, headers=headers_auth, timeout=30)
    
    if resp.status_code == 200:
        data       = resp.json().get("data", {})
        attributes = data.get("attributes", {})
        csv_rows.append({
            "device_id":        device_id,
            "server_id":        data.get("id", ""),
            "server_type":      data.get("type", ""),
            "serverName":       attributes.get("serverName", ""),
            "serverCategory":   attributes.get("serverType", ""),      # MDM / APPLE_CONFIGURATOR
            "createdDateTime":  attributes.get("createdDateTime", ""),
            "updatedDateTime":  attributes.get("updatedDateTime", "")
        })
        found += 1
        print(f"Device found : {device_id}")  # Print the message when device is found
    elif resp.status_code == 404:
        print(f"Device not found: {device_id}")
        failed += 1
    else:
        print(f"Error {resp.status_code} for {device_id}: {resp.text}")
        failed += 1
    time.sleep(0.2)   # respect API rate limits
    
# --------------------------------------------------------------------
# Write CSV output
# --------------------------------------------------------------------
csv_file = "device_assigned_servers.csv"
fieldnames = [
    "device_id",
    "server_id",
    "server_type",
    "serverName",
    "serverCategory",
    "createdDateTime",
    "updatedDateTime"
]
with open(csv_file, "w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(csv_rows)
    
print("\nSummary")
print(f"Devices succeeded: {found}")
print(f"Devices failed   : {failed}")
print(f"CSV written to   : {csv_file}")