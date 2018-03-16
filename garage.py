#!/usr/bin/env python3

#garage door opener

import os
import sys
import logging
import logging.handlers
import time
import socket
import struct
import threading
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64
from doorutil import toggle_garage_door, set_connected_light, set_power_light
from flask import Flask, request

loglevel = logging.INFO

#shamelessly stolen from stackoverflow
def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def read_private_key():
    with open("/etc/pygarage/key") as keyfile:
        for line in keyfile:
            key = base64.b64decode(line.strip())
            if len(key) != 32:
                continue

        return key

def check_connectivity():
    host=get_default_gateway_linux()
    port=80
    timeout=3

    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        set_connected_light(True)
    except:
        set_connected_light(False)

    threading.Timer(5, check_connectivity).start()

#eventually this will return encrypted shit but really the info flow is 1-way so there's no need
def parser(msg):
    print(msg)
    greeting = msg.startswith("GARAGEMAGIC")
    if not greeting:
        return "BADMAGIC"
    try:
        b64decoded = base64.urlsafe_b64decode(msg[11:])
    except:
        return "BADDECODE"
    nonce = b64decoded[0:12]
    aad = b64decoded[12:24]
    ciphertext = b64decoded[24:]

    chacha = ChaCha20Poly1305(read_private_key())
    try:
        decmsg = chacha.decrypt(nonce, ciphertext, aad)
    except:
        return "BADCRYPTO"

    if not decmsg.startswith(b"OPEN"):
        return "BADCMD"

    cmdtime = int(aad)
    print(cmdtime)
    if abs(cmdtime-time.time()) > 5:
        return "BADTIME"

    #need to take an action here
    toggle_garage_door();
    return "OK"


if __name__ == '__main__':
    logger = logging.getLogger("pygarage")
    logger.setLevel(loglevel)
    if not len(logger.handlers):
        loghandler = logging.handlers.SysLogHandler(address = '/dev/log')
        loghandler.setFormatter(logging.Formatter("[PyGarage]: %(message)s"))
        logger.addHandler(loghandler)
    logger.info("PyGarage starting")
    check_connectivity()
    set_power_light(True)

    app = Flask(__name__)
    @app.route("/open")
    def handle():
        return parser(request.args.get('cmd', ''))

    @app.route("/time")
    def gettime():
        return "%i" % time.time()

    app.run(host='0.0.0.0')

    logger.info("Exiting")
    set_power_light(False)
