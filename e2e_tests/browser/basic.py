#!/usr/bin/python3

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import subprocess
from time import sleep
import os
import sys

def assert_running(process):
    try:
        code = process.wait(1)
        raise Exception("Server died with return code %d" % code)
    except subprocess.TimeoutExpired:
        pass

def eprint(msg):
    print(msg, file=sys.stderr)

port = 4242

server = subprocess.Popen(["cargo", "run", "--manifest-path", "selfhost-dashboard/Cargo.toml", "--features=mock_system", "--", "--bind-port", str(port), "--pg-uri=x"])

try:
    sleep(3)
    # Check that the server started
    assert_running(server)

    uri = "http://localhost:" + str(port) + "/dashboard"

    chrome_options = webdriver.ChromeOptions()
    try:
        if os.environ["HEADLESS_TEST"] == "1":
            chrome_options.add_argument("headless")
    except:
        pass

    driver = webdriver.Chrome("/usr/bin/chromedriver", chrome_options=chrome_options)

    eprint("Opening dashboard")
    driver.get(uri)
    eprint("Registering admin")
    driver.find_element_by_name("password").send_keys("123")
    driver.find_element_by_name("re-password").send_keys("123")
    driver.find_element_by_name("password").send_keys(Keys.RETURN)
    eprint("Logging out")
    driver.get(uri + "/logout")
    eprint("Logging in")
    driver.find_element_by_name("username").send_keys("admin")
    driver.find_element_by_name("password").send_keys("123")
    driver.find_element_by_name("password").send_keys(Keys.RETURN)

    time.sleep(1)
    # Check that the server didn't die during test
    assert_running(server)

finally:
    if server.returncode is None:
        server.kill()
