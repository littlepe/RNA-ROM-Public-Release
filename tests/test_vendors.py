# -*- coding: utf-8 -*-
"""Tests for the vendor modules, they never touch the network."""

from __future__ import print_function

import base64
import json

from getrom import crypto
from getrom.vendors import coloros, obric

COLOROS_KEY = bytes(range(32))
COLOROS_IV = bytes(range(16))


def test_coloros_query_branch(monkeypatch):
    """The ColorOS query has to decrypt the answer and pick the firmware up."""
    def fake_urandom(size):
        """Return a fixed random sequence so the test is reproducible.

        Args:
            size: The number of bytes.

        Returns:
            bytes: The fixed data.
        """
        return (COLOROS_KEY * 4)[:size]

    def fake_request(url, data=None, headers=None, timeout=30):
        """Act as the ColorOS server.

        Args:
            url: The address.
            data: The request body.
            headers: The request headers.
            timeout: The timeout.

        Returns:
            bytes: The encrypted answer.
        """
        request = json.loads(data)
        params = json.loads(request["params"])
        cipher = base64.b64decode(params["cipher"])
        plain = crypto.aes_ctr(cipher, COLOROS_KEY, base64.b64decode(params["iv"]))
        body = json.loads(plain.decode("utf-8"))
        assert body["opex"]["check"] is True
        payload = {
            "versionName": "ColorOS 16.0.0",
            "otaVersion": "PLK110_11.F.01_0001",
            "components": [{
                "componentPackets": {
                    "manualUrl": "https://example.com/ota.zip",
                    "md5": "0123456789abcdef",
                    "size": 1024,
                }
            }],
        }
        blob = json.dumps(payload).encode("utf-8")
        enc = crypto.aes_ctr(blob, COLOROS_KEY, COLOROS_IV)
        reply = {
            "responseCode": 200,
            "body": json.dumps({
                "cipher": base64.b64encode(enc).decode(),
                "iv": base64.b64encode(COLOROS_IV).decode(),
            }),
        }
        return json.dumps(reply).encode("utf-8")

    monkeypatch.setattr(coloros.os, "urandom", fake_urandom)
    monkeypatch.setattr(coloros, "http_request", fake_request)
    result = coloros.query_branch("PLK110", "F")
    assert result["code"] == 200
    assert result["version"] == "ColorOS 16.0.0"
    assert result["link"] == "https://example.com/ota.zip"
    assert result["md5"] == "0123456789abcdef"


def test_obric_signature_is_stable():
    """The Obric signature depends on the body and stays the same."""
    body = '{"product":"Pacific"}'
    first = obric.sign("secret", body)
    assert first == obric.sign("secret", body)
    assert first != obric.sign("secret", '{"product":"Ocean2"}')


def test_obric_package_selection():
    """Obric prefers the full package."""
    packages = [{"type": "2", "version": "a"}, {"type": "1", "version": "b"}]
    assert obric.choose_package(packages)["version"] == "b"
    assert obric.choose_package([]) is None
