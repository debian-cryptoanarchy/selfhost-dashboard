#!/usr/bin/python3

import requests
import subprocess
import time

def assert_running(process):
    try:
        code = process.wait(1)
        raise Exception("Server died with return code %d" % code)
    except subprocess.TimeoutExpired:
        pass

port = 4242

server = subprocess.Popen(["cargo", "run", "--manifest-path", "selfhost-dashboard/Cargo.toml", "--features=mock_system", "--", "--bind-port", str(port), "--pg-uri=x"])

try:
    time.sleep(3)
    # Check that the server started
    assert_running(server)

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
    thunderhub = session.get(uri + "/open-app/thunderhub-mainnet")
    assert thunderhub.status_code == 404
    assert thunderhub.url.endswith("/thunderhub?token=this_is_a_test")
    assert session.get(uri + "/logout").status_code == 200
    bad_password = session.post(uri + "/login", data = {"username": "admin", "password": "567"})
    assert bad_password.status_code == 200
    assert bad_password.url.endswith("#failure=credentials")
    bad_input = session.post(uri + "/login", data = {"username": "admin"})
    assert bad_input.status_code == 200
    assert bad_input.url.endswith("#failure=input")

    sleep(1)
    # Check that the server didn't die during test
    assert_running(server)

finally:
    if server.returncode is None:
        server.kill()
