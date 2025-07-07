#!/usr/bin/python3

# Script: getMDMServer_ASM.py
# Karthikeyan Marappan
#
# Purpose
#
# Query Apple business Manager (ABM) to fetch device information, including assigned server and other details.
#
# It follows Apple’s JWT-based OAuth flow documented here: https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api
#
# Replace the placeholder values below (`Certificate.pem`, client_id, device_ids_file etc.) with your own ABM credentials. (https://support.apple.com/en-ca/guide/apple-business-manager/axm33189f66a/1/web/1)
#
# CLIENT_ASSERTION_VALIDITY_DAYS # Validity of assertion and Apple support max of 180 days

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
private_key_file        = "Certificate.pem"                 # EC private key (.pem)
client_assertion_file   = "client_assertion.json" 
client_id               = "businessAPI.xxx-ca0b-482d-xx-xxxxxxxxx"
team_id                 = "businessAPI.xxx-ca0b-482d-xx-xxxxxxxxx"
key_id                  = "xxxx-3fa5-4001-xx-xx"
audience                = "https://account.apple.com/auth/oauth2/v2/token"
jwt_alg                 = "ES256"
scope                   = "business.api"
serialNumberList        = "serialnumbers.txt"  # path of serial number list

# --------------------------------------------------------------------
# How long (in days) the next JWT should stay valid.
# Edit this number whenever you want a different lifetime.
# Apple allows 1 – 180 days.
# --------------------------------------------------------------------

CLIENT_ASSERTION_VALIDITY_DAYS = 1      # ← change me

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
# Helper: reuse client_assertion if it is still valid (not expired)
# --------------------------------------------------------------------
def load_valid_client_assertion() -> str | None:
    """
    Return the cached client_assertion if its exp claim is still in the future.
    Otherwise return None so that the script can generate a new one.
    """
    if not os.path.exists(client_assertion_file):
        return None
    
    try:
        with open(client_assertion_file, "r") as f:
            cached = json.load(f)
            
        exp = int(cached.get("exp", 0))                  # expiry (epoch seconds)
        now = int(dt.datetime.utcnow().timestamp())      # current time (UTC)
        
        # allow 60-second clock-skew safety margin
        if exp > now + 60:
            remaining_days = (exp - now) // 86_400
            print(f"Using cached client assertion "
                  f"(≈ {remaining_days} days remaining).")
            return cached["client_assertion"]
        
    except Exception as err:
        # any problem – fall through and create a fresh assertion
        print(f"Could not reuse cached assertion: {err}")
        
    return None

# --------------------------------------------------------------------
# Helper: generate and cache a new client_assertion (valid 180 days)
# --------------------------------------------------------------------
def generate_client_assertion() -> str:
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
# Query device information for each device with specific fields
# --------------------------------------------------------------------
base_url      = "https://api-business.apple.com/v1/orgDevices"
fields        = "serialNumber,addedToOrgDateTime,updatedDateTime,deviceModel,productFamily,productType,deviceCapacity,partNumber,orderNumber,color,status,orderDateTime,imei,meid,eid,purchaseSourceId,purchaseSourceType,assignedServer"
headers_auth  = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
csv_rows      = []
found, failed = 0, 0

for device_id in device_ids:
    # Modify the URL to include the fields query parameter
    url = f"{base_url}/{device_id}?fields[orgDevices]={fields}"  # Adding the fields query
    resp = requests.get(url, headers=headers_auth, timeout=30)
    
    if resp.status_code == 200:
        data       = resp.json().get("data", {})
        attributes = data.get("attributes", {})
        csv_rows.append({
            "device_id":        device_id,
            "serialNumber":     attributes.get("serialNumber", ""),
            "addedToOrgDateTime": attributes.get("addedToOrgDateTime", ""),
            "updatedDateTime":  attributes.get("updatedDateTime", ""),
            "deviceModel":      attributes.get("deviceModel", ""),
            "productFamily":    attributes.get("productFamily", ""),
            "productType":      attributes.get("productType", ""),
            "deviceCapacity":   attributes.get("deviceCapacity", ""),
            "partNumber":       attributes.get("partNumber", ""),
            "orderNumber":      attributes.get("orderNumber", ""),
            "color":            attributes.get("color", ""),
            "status":           attributes.get("status", ""),
            "orderDateTime":    attributes.get("orderDateTime", ""),
            "imei":             attributes.get("imei", ""),
            "meid":             attributes.get("meid", ""),
            "eid":              attributes.get("eid", ""),
            "purchaseSourceId": attributes.get("purchaseSourceId", ""),
            "purchaseSourceType": attributes.get("purchaseSourceType", "")
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
csv_file = "device_info.csv"  # Renamed to reflect the updated data
fieldnames = [
    "device_id",
    "serialNumber",
    "addedToOrgDateTime",
    "updatedDateTime",
    "deviceModel",
    "productFamily",
    "productType",
    "deviceCapacity",
    "partNumber",
    "orderNumber",
    "color",
    "status",
    "orderDateTime",
    "imei",
    "meid",
    "eid",
    "purchaseSourceId",
    "purchaseSourceType"
]
with open(csv_file, "w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(csv_rows)
    
print("\nSummary")
print(f"Devices succeeded: {found}")
print(f"Devices failed   : {failed}")
print(f"CSV written to   : {csv_file}")