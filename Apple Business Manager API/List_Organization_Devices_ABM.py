#!/usr/bin/python3

# Script: List_Organization_Devices_ABM.py
# Karthikeyan Marappan
#
# Purpose
#
# Query Apple business Manager (ABM) to get a list of devices in an organization that enroll using Automated Device Enrollment. (https://developer.apple.com/documentation/applebusinessmanagerapi/get-org-devices)
#
#It follows Apple’s JWT-based OAuth flow documented here: https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api
#
#Replace the placeholder values below (`Certificate.pem`, client_id, device_ids_file etc.) with your own ABM credentials. (https://support.apple.com/en-ca/guide/apple-business-manager/axm33189f66a/1/web/1)
#
# CLIENT_ASSERTION_VALIDITY_DAYS #Validity of assertion and Apple support max of 180 days


import os, requests, json, csv
import datetime as dt
import uuid as uuid
from authlib.jose import jwt
from Crypto.PublicKey import ECC

# --------------------------------------------------------------------
# Apple Business Manager OAuth configuration (Configure Variables)
# --------------------------------------------------------------------

private_key_file      = "Certificate.pem"                  # path of EC private key (.pem)
client_assertion_file = "client_assertion.json"            # cache for JWT + expiry
client_id             = "businessAPI.rstuvw-1f50-efgh-abcd-ijklmnop"
team_id               = "businessAPI.rstuvw-1f50-efgh-abcd-ijklmnop"
key_id                = "be678907667-888h-40ec-abcd-9m8n7b6v"
audience              = "https://account.apple.com/auth/oauth2/v2/token"
jwt_alg               = "ES256"
scope                 = "business.api"

# --------------------------------------------------------------------
# How long (in days) the next JWT should stay valid.# Apple allows 1 – 180 days.
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
    exp    = issued + 86_400 * CLIENT_ASSERTION_VALIDITY_DAYS                       
    
    header = {"alg": jwt_alg, "kid": key_id}
    payload = {
        "sub": client_id,
        "aud": audience,
        "iat": issued,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "iss": team_id,
    }
    
    with open(private_key_file, "r") as f:
        priv_key = ECC.import_key(f.read())
        
    assertion = jwt.encode(
        header=header,
        payload=payload,
        key=priv_key.export_key(format="PEM"),
    ).decode("utf-8")
    
    with open(client_assertion_file, "w") as f:
        json.dump({"client_assertion": assertion, "exp": exp}, f)
        
    print("Generated new client assertion.")
    return assertion


# Decide which assertion to use
client_assertion = load_valid_client_assertion() or generate_client_assertion()


url = "https://account.apple.com/auth/oauth2/token"

headers = {
    "Host": "account.apple.com",
    "Content-Type": "application/x-www-form-urlencoded"
}

data = {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": client_assertion,
    "scope": scope
}

response = requests.post(url, headers=headers, data=data)

if response.status_code == 200:
    access_token = response.json().get("access_token")
    # print("Access Token:", access_token)
else:
    print("Failed to get access token:", response.status_code, response.text)

base_url = "https://api-business.apple.com/v1/orgDevices"

# Define the fields to request and save
fields = [
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
    "purchaseSourceType",
    "assignedServer"
]

params_url = {
    "fields[orgDevices]": ",".join(fields),
    "limit": 100
}

cursor = None
all_devices = []
page = 1

devices_headers = {
    "Authorization": f"Bearer {access_token}",
    "Accept": "application/json"
}

while True:
    print(f"Fetching page {page}...")
    
    params = dict(params_url)  # copy base params
    if cursor:
        params["cursor"] = cursor
        
    response = requests.get(base_url, headers=devices_headers, params=params)
    print(f"Status code: {response.status_code}")
    
    if response.status_code != 200:
        print(f"Failed to fetch devices: {response.status_code}")
        break
    
    data = response.json()
    devices = data.get("data", [])
    print(f"Devices in this page: {len(devices)}")
    all_devices.extend(devices)
    
    # Print each device in block format
    for device in devices:
        print("\n--- Device ---")
        for field in fields:
            print(f"{field}: {device.get('attributes', {}).get(field, '')}")
            
    # Handle pagination
    paging = data.get("meta", {}).get("paging", {})
    cursor = paging.get("nextCursor")
    if not cursor:
        break
    page += 1
    
print(f"\nFinished. Total devices fetched: {len(all_devices)}")

# Write to CSV
csv_file = "org_devices.csv"
with open(csv_file, mode='w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for device in all_devices:
        row = {field: device.get("attributes", {}).get(field, "") for field in fields}
        writer.writerow(row)
        
print(f"Device details saved to {csv_file}")