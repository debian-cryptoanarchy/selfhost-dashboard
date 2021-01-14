#!/usr/bin/python3

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import subprocess
from time import sleep
import os
import sys

def eprint(msg):
    print(msg, file=sys.stderr)

port = 4242

server = subprocess.Popen(["cargo", "run", "--features=mock_system", "--", "--bind-port", str(port), "--pg-uri=x"])

try:
    sleep(3)

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
    driver.find_element_by_name("username").send_keys("admin")
    driver.find_element_by_name("password").send_keys("123")
    driver.find_element_by_name("password").send_keys(Keys.RETURN)
    eprint("Logging out")
    driver.get(uri + "/logout")
    eprint("Logging in")
    driver.find_element_by_name("username").send_keys("admin")
    driver.find_element_by_name("password").send_keys("123")
    driver.find_element_by_name("password").send_keys(Keys.RETURN)

finally:
    server.kill()
