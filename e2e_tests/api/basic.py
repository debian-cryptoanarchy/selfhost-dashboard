#!/usr/bin/python3

import requests
import subprocess
import time

port = 4242

server = subprocess.Popen(["cargo", "run", "--features=mock_system", "--", "--bind-port", str(port), "--pg-uri=x"])

try:
    time.sleep(3)

    uri = "http://localhost:" + str(port) + "/dashboard"

    entered = requests.get(uri)
    assert entered.status_code == 200
    assert entered.url.endswith("/dashboard/login#uninitialized=true")

    session = requests.Session()
    assert session.post(uri + "/login", data = {"username": "admin", "password": "123"}).status_code == 200
    apps_resp = session.get(uri + "/apps")
    assert apps_resp.status_code == 200
    apps = apps_resp.json()
    # There should be a field called apps containing a non-empty array
    val = apps["apps"][0]
    assert session.get(uri + "/logout").status_code == 200
    bad_password = session.post(uri + "/login", data = {"username": "admin", "password": "567"})
    assert bad_password.status_code == 200
    assert bad_password.url.endswith("#failure=credentials")
    bad_input = session.post(uri + "/login", data = {"username": "admin"})
    assert bad_input.status_code == 200
    assert bad_input.url.endswith("#failure=input")

finally:
    server.kill()
