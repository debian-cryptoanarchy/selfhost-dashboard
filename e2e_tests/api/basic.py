#!/usr/bin/python3

import requests
import subprocess
import time

port = 4242

server = subprocess.Popen(["cargo", "run", "--features=mock_system", "--", "--bind-port", str(port), "--pg-uri=x"])

try:
    time.sleep(3)

    uri = "http://localhost:" + str(port) + "/dashboard"

    assert requests.get(uri).status_code == 200

    session = requests.Session()
    assert session.post(uri + "/login", data = {"username": "admin", "password": "123"}).status_code == 200
    apps_resp = session.get(uri + "/apps")
    assert apps_resp.status_code == 200
    apps = apps_resp.json()
    # There should be a field called apps containing a non-empty array
    val = apps["apps"][0]

finally:
    server.kill()
