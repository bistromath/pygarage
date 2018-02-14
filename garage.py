#!/usr/bin/env python3

#garage door opener

import os
import sys
import logging
import logging.handlers
import socket
import select
import struct
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64
from doorutil import toggle_garage_door, set_connected_light, set_power_light

#keep this secret, eh
key = b''

loglevel = logging.INFO

def check_connectivity():
    host="192.168.29.1"
    port=80
    timeout=3

    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        set_connected_light(True)
    except:
        set_connected_light(False)

    threading.Timer(5, check_connectivity).start()

class tcp_server(threading.Thread):
    def __init__(self, port, parser, logger):
        threading.Thread.__init__(self)
        self.logger = logger
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(('0.0.0.0', port))
        self._sock.listen(1)
        self._sock.setblocking(0)
        NOLINGER = struct.pack('ii', 1, 0)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, NOLINGER)
        self.setDaemon(True)
        self._running=True

        self._parser = parser

    def stop(self):
        self._running=False

    def wait(self):
        while(self._running):
            1

    def run(self):
        ins = [self._sock]
        outs = []
        msgqs = {}
        while self._running:
            # poll for bad descriptors here
            ins[:] = [i for i in ins if i.fileno() != -1]
            outs[:] = [i for i in outs if i.fileno() != -1]
            readable, writeable, bad = select.select(ins, outs, ins)
            for s in readable:
                if s is self._sock:
                    conn,addr = s.accept()
                    logger.info("New connection")
                    conn.setblocking(0)
                    ins.append(conn)
                    outs.append(conn)
                    msgqs[conn] = b""
                else:
                    d = s.recv(1024)
                    if d:
                        logger.info("New message from %s: %s" % (s.getpeername(), d))
                        msgqs[s] += d
                    else:
                        logger.info("Connection closed")
                        ins.remove(s)
                        s.close()

            for k,v in msgqs.items():
                if len(v) > 0:
                    if v.endswith(b"\n"):
                        logger.debug("Parsing!")
                        #parse the message here
                        retstr = self._parser(v.strip())+'\n'
                        logger.info("Returning: %s" % retstr)
                        try:
                            for out in outs:
                                out.send(bytes(retstr, 'utf-8'))
                        except Exception as e:
                            logger.warning("Exception: %s" % e)
                            pass
                        msgqs[k] = b""
        for s in ins:
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except:
                pass
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
        except:
            pass

#eventually this will return encrypted shit but really the info flow is 1-way so there's no need
def parser(msg):
    print(msg)
    greeting = msg.startswith(b"GARAGEMAGIC")
    if not greeting:
        return "BADMAGIC"
    try:
        b64decoded = base64.b64decode(msg[11:])
    except:
        return "BADDECODE"
    nonce = b64decoded[0:12]
    aad = b64decoded[12:24]
    ciphertext = b64decoded[24:]

    chacha = ChaCha20Poly1305(key)
    try:
        decmsg = chacha.decrypt(nonce, ciphertext, aad)
    except:
        return "BADCRYPTO"

    if not decmsg.startswith(b"OPEN"):
        return "BADCMD"

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
    tcpserver = tcp_server(33103, parser, logger)
    tcpserver.start()
    check_connectivity()
    set_power_light(True)

    while True:
        try:
            time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Exiting")
            set_power_light(False)
            sys.exit()
