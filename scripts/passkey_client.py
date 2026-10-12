#!/usr/bin/env python3
"""A software WebAuthn authenticator for scripts/demo.sh.

It builds, from the options route's response (a challenge id and the options), the JSON a browser would pass back after
navigator.credentials.create and .get. It shares no code with the server or with the Go test
helper, so the demo also shows that an independent implementation is accepted.

    passkey_client.py STATE RP_ID ORIGIN register RESPONSE.json
    passkey_client.py STATE RP_ID ORIGIN assert RESPONSE.json

STATE is a private JSON file holding the key, the credential ID and the user handle; the demo
keeps it under .secrets/demo. The authenticator uses ES256, verifies the user, and reports a
signature counter that grows by one per assertion. Only the standard library and the openssl
command line are used.
"""
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# A minimal CBOR encoder for the few shapes WebAuthn needs: small integers, byte and text
# strings, and maps.
def cbor(value):
    if isinstance(value, bool):
        raise TypeError("booleans are not used")
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + struct.pack(">H", n)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


def new_state(path):
    with tempfile.TemporaryDirectory() as tmp:
        key = os.path.join(tmp, "key.pem")
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        pem = open(key).read()
        text = openssl("ec", "-in", key, "-noout", "-text").decode()
    point = bytes.fromhex("".join(re.findall(r"[0-9a-f]{2}", text.split("pub:")[1].split("ASN1")[0])))
    state = {
        "pem": pem, "x": b64(point[1:33]), "y": b64(point[33:65]), "credential_id": b64(os.urandom(32)),
        "user_handle": "", "counter": 0,
    }
    save(path, state)
    return state


def save(path, state):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)


def client_data(kind, challenge, origin):
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()


def sign(state, message):
    with tempfile.TemporaryDirectory() as tmp:
        key = os.path.join(tmp, "key.pem")
        with open(key, "w") as f:
            f.write(state["pem"])
        return openssl("dgst", "-sha256", "-sign", key, data=message)


def main():
    path, rp_id, origin, command, options_file = sys.argv[1:6]
    document = json.load(open(options_file))
    options = document.get("options", document)["publicKey"]  # the server wraps the options with the challenge id
    state = json.load(open(path)) if os.path.exists(path) else None
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    cred_id = None

    if command == "register":
        state = state or new_state(path)
        state["user_handle"] = options["user"]["id"]
        cred_id = unb64(state["credential_id"])
        cose = cbor({1: 2, 3: -7, -1: 1, -2: unb64(state["x"]), -3: unb64(state["y"])})
        # flags: user present, user verified, attested credential data included
        auth_data = rp_hash + bytes([0x45]) + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", len(cred_id)) + cred_id + cose
        attestation = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        save(path, state)
        out = {
            "id": state["credential_id"], "rawId": state["credential_id"], "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data("webauthn.create", options["challenge"], origin)),
                "attestationObject": b64(attestation), "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }
    elif command == "assert":
        if state is None:
            sys.exit("no passkey registered in " + path)
        state["counter"] += 1
        auth_data = rp_hash + bytes([0x05]) + struct.pack(">I", state["counter"])  # user present and verified
        data = client_data("webauthn.get", options["challenge"], origin)
        signature = sign(state, auth_data + hashlib.sha256(data).digest())
        save(path, state)
        out = {
            "id": state["credential_id"], "rawId": state["credential_id"], "type": "public-key",
            "response": {
                "clientDataJSON": b64(data), "authenticatorData": b64(auth_data), "signature": b64(signature),
                "userHandle": state["user_handle"],
            },
            "clientExtensionResults": {},
        }
    else:
        sys.exit("unknown command " + command)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
