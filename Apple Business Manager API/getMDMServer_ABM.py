#!/usr/bin/python3

# Script: getMDMServer_ABM.py
# Karthikeyan Marappan
#
# Purpose
#
# Query Apple business Manager (ABM) to fetch the assigned device management service information for a device(https://developer.apple.com/documentation/applebusinessmanagerapi/get-the-assigned-server-information-for-an-orgdevice)
#
#It follows Apple’s JWT-based OAuth flow documented here: https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api
#
#Replace the placeholder values below (`Certificate.pem`, client_id, device_ids_file etc.) with your own ABM credentials. (https://support.apple.com/en-ca/guide/apple-business-manager/axm33189f66a/1/web/1)
# v1.1 Regenerate client assertion if fetching access token fails.
# CLIENT_ASSERTION_VALIDITY_DAYS #Validity of assertion and Apple support max of 180 days

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
# Apple business Manager OAuth configuration
# --------------------------------------------------------------------
private_key_file      = "Certificate.pem"                  # path of EC private key (.pem)
client_assertion_file = "client_assertion.json"            # cache for JWT + expiry
client_id             = "businessAPI.rstuvw-1f50-efgh-abcd-ijklmnop"
team_id               = "businessAPI.rstuvw-1f50-efgh-abcd-ijklmnop"
key_id                = "be678907667-888h-40ec-abcd-9m8n7b6v"
audience              = "https://account.apple.com/auth/oauth2/v2/token"
jwt_alg               = "ES256"
scope                 = "business.api"
serialNumberList      = "serialnumbers.txt" # path of serial number list

# --------------------------------------------------------------------
# How long (in days) the next JWT should stay valid.
# Edit this number whenever you want a different lifetime.
# Apple allows 1 – 180 days.
# --------------------------------------------------------------------

CLIENT_ASSERTION_VALIDITY_DAYS = 10      # ← change me

# validate and clamp to Apple’s limits
if CLIENT_ASSERTION_VALIDITY_DAYS > 180:
        print(f"Requested {CLIENT_ASSERTION_VALIDITY_DAYS} days – "
                    "Apple allows max 180, so I’ll use 180 instead.")
        CLIENT_ASSERTION_VALIDITY_DAYS = 180
elif CLIENT_ASSERTION_VALIDITY_DAYS < 1:
        print(f"Requested {CLIENT_ASSERTION_VALIDITY_DAYS} days – "
                    "must be at least 1, so I’ll use 1 instead.")
        CLIENT_ASSERTION_VALIDITY_DAYS = 1
    
    
    
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
# Load existing assertion if valid
# --------------------------------------------------------------------
def load_valid_client_assertion():
    if not os.path.exists(client_assertion_file):
        return None
    try:
        with open(client_assertion_file, "r") as f:
            cached = json.load(f)
        exp = int(cached.get("exp", 0))
        now = int(dt.datetime.utcnow().timestamp())
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
    exp = issued + 86400 * CLIENT_ASSERTION_VALIDITY_DAYS
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
# Query assignedServer for each device
# --------------------------------------------------------------------
def get_assigned_mdm_server(device_ids, access_token):
    base_url      = "https://api-business.apple.com/v1/orgDevices"
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
    
# --------------------------------------------------------------------
# Main Execution Flow
# --------------------------------------------------------------------
    
# Try cached or generate a client assertion
client_assertion = load_valid_client_assertion() or generate_client_assertion()

# First attempt to get access token
token_resp = request_access_token(client_assertion)
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

device_ids = read_device_ids_from_txt(serialNumberList)
get_assigned_mdm_server(device_ids, access_token)
