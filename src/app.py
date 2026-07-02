import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("googlefindmy")

from fastapi import FastAPI
app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def status():
    return


from GoogleFindMyTools.NovaApi.nova_request import nova_request
from GoogleFindMyTools.NovaApi.ListDevices.nbe_list_devices import request_device_list
from GoogleFindMyTools.NovaApi.ExecuteAction.LocateTracker.location_request import create_location_request
from GoogleFindMyTools.NovaApi.ExecuteAction.LocateTracker.decrypt_locations import retrieve_identity_key
from GoogleFindMyTools.NovaApi.ExecuteAction.LocateTracker.decrypted_location import WrappedLocation
from GoogleFindMyTools.NovaApi.util import generate_random_uuid
from GoogleFindMyTools.NovaApi.scopes import NOVA_ACTION_API_SCOPE
from GoogleFindMyTools.ProtoDecoders import Common_pb2, DeviceUpdate_pb2
from GoogleFindMyTools.ProtoDecoders.decoder import parse_device_list_protobuf, parse_device_update_protobuf
from GoogleFindMyTools.FMDNCrypto.foreign_tracker_cryptor import decrypt
from GoogleFindMyTools.KeyBackup.cloud_key_decryptor import decrypt_aes_gcm
from GoogleFindMyTools.Auth.fcm_receiver import FcmReceiver

from google.protobuf.json_format import MessageToDict
import time
import hashlib
from datetime import datetime


# @app.get("/devices")
# def get_devices():
#     result_hex = request_device_list()
#     device_list = parse_device_list_protobuf(result_hex)
#     return MessageToDict(device_list)["deviceMetadata"]
@app.get("/devices")
def get_devices():
    device_list = request_device_list()
    device_list = parse_device_list_protobuf(device_list)
    device_list = MessageToDict(device_list)["deviceMetadata"]

    devices = []
    for i, device in enumerate(device_list):
        if device["identifierInformation"]["type"] == "IDENTIFIER_ANDROID":
            print(f"HOLA: {device}")
            device_id = (
                device.get("identifierInformation", {})
                .get("phoneInformation", {})
                .get("canonicIds", {})
                .get("canonicId", [{}])[0]
                .get("id")
            )
        else:
            device_id = device["identifierInformation"]["canonicIds"]["canonicId"][0]["id"]
        if not device_id:
            continue
        locations = get_location_data_for_device(device_id)
        latest = locations[-1] if locations else {}

        devices.append({
            "id": i + 1,
            "hardware_id": device_id,
            "name": device.get("userDefinedDeviceName"),
            "assigned_asset": f"Asset {i+1}",
            "status": "online",
            "battery_level": 0,
            "last_sync": latest.get("time"),
            "created_at": "2026-07-01T17:23:13.808862",
            "latitude": latest.get("latitude"),
            "longitude": latest.get("longitude"),
            "altitude": latest.get("altitude"),
            "speed": 0.0,
        })
    return devices


def decrypt_location_response_locations(device_update_protobuf):
    device_registration = device_update_protobuf.deviceMetadata.information.deviceRegistration

    identity_key = retrieve_identity_key(device_registration)
    locations_proto = device_update_protobuf.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations

    # At All Areas Reports or Own Reports
    recent_location = locations_proto.recentLocation
    recent_location_time = locations_proto.recentLocationTimestamp

    # High Traffic Reports
    network_locations = list(locations_proto.networkLocations)
    network_locations_time = list(locations_proto.networkLocationTimestamps)

    if locations_proto.HasField("recentLocation"):
        network_locations.append(recent_location)
        network_locations_time.append(recent_location_time)

    location_time_array = []
    for loc, time in zip(network_locations, network_locations_time):

        if loc.status == Common_pb2.Status.SEMANTIC:
            wrapped_location = WrappedLocation(
                decrypted_location=b'',
                time=int(time.seconds),
                accuracy=0,
                status=loc.status,
                is_own_report=True,
                name=loc.semanticLocation.locationName
            )
            location_time_array.append(wrapped_location)
        else:

            encrypted_location = loc.geoLocation.encryptedReport.encryptedLocation
            public_key_random = loc.geoLocation.encryptedReport.publicKeyRandom

            if public_key_random == b"":  # Own Report
                identity_key_hash = hashlib.sha256(identity_key).digest()
                decrypted_location = decrypt_aes_gcm(identity_key_hash, encrypted_location)
            else:
                time_offset = loc.geoLocation.deviceTimeOffset
                decrypted_location = decrypt(identity_key, encrypted_location, public_key_random, time_offset)

            wrapped_location = WrappedLocation(
                decrypted_location=decrypted_location,
                time=int(time.seconds),
                accuracy=loc.geoLocation.accuracy,
                status=loc.status,
                is_own_report=loc.geoLocation.encryptedReport.isOwnReport,
                name=""
            )
            location_time_array.append(wrapped_location)

    if not location_time_array:
        return []

    result = []
    for loc in location_time_array:

        if loc.status == Common_pb2.Status.SEMANTIC:
            print(f"Semantic Location: {loc.name}")
            continue

        else:
            proto_loc = DeviceUpdate_pb2.Location()
            proto_loc.ParseFromString(loc.decrypted_location)

            latitude = proto_loc.latitude / 1e7
            longitude = proto_loc.longitude / 1e7
            altitude = proto_loc.altitude

        result.append({
            "latitude": latitude,
            "longitude": longitude,
            "altitude": altitude,
            "time": datetime.fromtimestamp(loc.time).isoformat(timespec="microseconds"),
            "status": loc.status,
            "is_own_report": loc.is_own_report
        })
    return result

fcm = FcmReceiver()
def print_location_update(response):
    update = parse_device_update_protobuf(response)
    locations = decrypt_location_response_locations(update)
    print(f"[FCMReceiver] Received location update: {locations}")

def get_location_data_for_device(canonic_device_id):
    request_uuid = generate_random_uuid()

    result = None
    def handle_location_response(response):
        nonlocal result
        device_update = parse_device_update_protobuf(response)
        if device_update.fcmMetadata.requestUuid == request_uuid:
            result = parse_device_update_protobuf(response)
    fcm.register_for_location_updates(print_location_update)
    fcm_token = fcm.register_for_location_updates(handle_location_response)

    hex_payload = create_location_request(canonic_device_id, fcm_token, request_uuid)
    nova_request(NOVA_ACTION_API_SCOPE, hex_payload)
    while result is None:
        time.sleep(0.1)
    return decrypt_location_response_locations(result)

# @app.get("/device/{device_id}")
# def get_device(device_id: str):
#     return get_location_data_for_device(device_id)
