#!/usr/bin/python3

import os
from typing import BinaryIO, Union

import hidraw

_cstate = b"Htemp99e"
_shuffle = (2, 4, 0, 7, 1, 6, 5, 3)
_ctmp = bytes([((_cstate[i] >> 4) | (_cstate[i] << 4)) & 0xff for i in range(8)])


# https://github.com/poempelfox/co2sensorsw/blob/master/co2sensord.c
def _decrypt(buf: bytes, key: bytes) -> bytes:
    assert len(buf) == 8
    assert len(key) == 8
    phase1 = bytearray(8)
    for j in range(8):
        phase1[_shuffle[j]] = buf[j]
    phase2 = [phase1[i] ^ key[i] for i in range(8)]
    phase3 = [(phase2[i] >> 3) | ((phase2[(i + 7) % 8] << 5) & 0xff) for i in range(8)]
    out = [(0x100 + phase3[i] - _ctmp[i]) & 0xff for i in range(8)]
    return bytes(out)


def init_sensor(dev: hidraw.HIDRaw, key: bytes):
    assert len(key) == 8
    dev.sendFeatureReport(key)


def read_sensor(dev: BinaryIO, key: bytes):
    buf = dev.read(8)
    return _parse(_decrypt(buf, key))


def generate_key() -> bytes:
    return os.urandom(8)


class Temperature:
    def __init__(self, raw: int):
        self.raw = raw

    def kelvin(self) -> float:
        return self.raw / 16.0

    def celsius(self) -> float:
        return self.kelvin() - 273.15

    def __repr__(self):
        return "Temperature(%s = %s°C)" % (self.raw, self.celsius())


class CO2:
    def __init__(self, raw: int):
        self.raw = raw

    def ppm(self) -> int:
        return self.raw

    def __repr__(self):
        return "CO2(%s ppm)" % self.ppm()


class Unknown:
    # noinspection PyShadowingBuiltins
    def __init__(self, type: int, raw: int):
        self.type = type
        self.raw = raw

    def __repr__(self):
        return "Unknown(type=0x%x, %s)" % (self.type, self.raw)


class FormatError(IOError):
    def __init__(self, msg):
        super(FormatError, self).__init__(msg)


def _parse(decrypted: bytes) -> Union[CO2, Temperature, Unknown]:
    expected_sum = sum(decrypted[0:3]) & 0xff
    if expected_sum != decrypted[3]:
        raise FormatError("Checksum mismatch: '%s'" % decrypted)
    if decrypted[4:] != b"\x0d\x00\x00\x00":
        raise FormatError("Padding mismatch: '%s'" % decrypted)
    raw = (decrypted[1] << 8) | decrypted[2]
    if decrypted[0] == 0x50:
        return CO2(raw)
    elif decrypted[0] == 0x42:
        return Temperature(raw)
    else:
        return Unknown(decrypted[0], raw)


def _main():
    import graphitesend
    import sys
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--graphite-server")
    parser.add_argument("--graphite-id", default='0')
    parser.add_argument("--http-host", default='127.0.0.1')
    parser.add_argument("--http-port", type=int)
    args = parser.parse_args()

    graphite = args.graphite_server is not None
    if graphite:
        graphitesend.init(graphite_server=args.graphite_server, prefix="co2mon." + args.graphite_id,
                          system_name="")

    state = {}

    if args.http_port:
        import flask
        import threading
        app = flask.Flask("co2mon")

        @app.route("/")
        def show_state():
            return flask.jsonify(state)

        def run():
            app.run(host=args.http_host, port=args.http_port)

        threading.Thread(target=run, daemon=True).start()

    with open(sys.argv[1], "r+b") as dev:
        key = generate_key()
        hid = hidraw.HIDRaw(dev.fileno())
        init_sensor(hid, key)
        while True:
            data = read_sensor(dev, key)
            if type(data) == CO2:
                if graphite:
                    graphitesend.send("co2", data.ppm())
                state["co2"] = data.ppm()
            elif type(data) == Temperature:
                if graphite:
                    graphitesend.send("temperature", data.celsius())
                state["temperature"] = data.celsius()


if __name__ == '__main__':
    _main()
