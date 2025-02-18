#!/usr/bin/env python3

import getpass
import json
import logging
import os
import re
import requests
import sys
import urllib.parse

from argparse import ArgumentParser
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.common.by import By

user_agent = {'User-Agent': 'krumpli'}
logger = logging.getLogger(__name__)


def create_session(backup_email=None, backup_password=None, backup_oath=None, browser_visible=True, proxy=None):
    # Only start a virtual display if browser_visible is False (i.e. headless mode)
    if not browser_visible:
        from pyvirtualdisplay import Display
        display = Display(visible=0)
        display.start()

    logger.info("Starting browser")
    options = webdriver.ChromeOptions()
    if proxy:
        options.add_argument('--proxy-server=' + proxy)
    # If browser_visible is True, we do not add the headless option.
    if not browser_visible:
        options.add_argument('--headless')
    browser = webdriver.Chrome(options=options)

    # --- Manual Login Phase ---
    logger.info("Opening Amazon Sign-In page for manual login")
    # Updated URL for manual login:
    browser.get('https://www.amazon.com/gp/sign-in.html')
    print("Please log in manually in the opened browser window (complete MFA if required).")
    input("After you've logged in, press Enter to continue...")

    logger.info("Navigating to digital console page to retrieve session data")
    browser.get('https://www.amazon.com/hz/mycd/digital-console/contentlist/booksAll/dateDsc/')
    
    # Attempt to extract the CSRF token and customer ID
    csrf_token = None
    match = re.search('var csrfToken = "(.*)";', browser.page_source)
    if match:
        csrf_token = match.group(1)

    custid = None
    match = re.search('customerId: \"(.*)\"', browser.page_source)
    if match:
        custid = match.group(1)

    # --- Fallback: Automated Login if Manual Login Fails ---
    if not csrf_token:
        print("Manual login did not seem to complete successfully.")
        answer = input("Would you like to attempt automated login with backup credentials? (y/n): ")
        if answer.strip().lower().startswith('y'):
            # If backup credentials weren't provided already, prompt for them now.
            if not (backup_email and backup_password and backup_oath):
                backup_email = input("Enter your Amazon email for automated login: ")
                backup_password = getpass.getpass("Enter your Amazon password for automated login: ")
                backup_oath = getpass.getpass("Enter your Amazon Oath for automated login: ")
            try:
                logger.info("Attempting automated login using backup credentials.")
                browser.get('https://www.amazon.com/gp/sign-in.html')
                browser.find_element(By.ID, "ap_email").clear()
                browser.find_element(By.ID, "ap_email").send_keys(backup_email)
                browser.find_element(By.CSS_SELECTOR, '.a-button-input').click()
                browser.find_element(By.ID, "ap_password").clear()
                browser.find_element(By.ID, "ap_password").send_keys(backup_password)
                browser.find_element(By.ID, "signInSubmit").click()
                browser.find_element(By.ID, "auth-mfa-otpcode").clear()
                browser.find_element(By.ID, "auth-mfa-otpcode").send_keys(backup_oath)
                browser.find_element(By.ID, "auth-signin-button").click()
                # Navigate again to the digital console page.
                browser.get('https://www.amazon.com/hz/mycd/digital-console/contentlist/booksAll/dateDsc/')
                match = re.search('var csrfToken = "(.*)";', browser.page_source)
                if match:
                    csrf_token = match.group(1)
                match = re.search('customerId: \"(.*)\"', browser.page_source)
                if match:
                    custid = match.group(1)
            except Exception as e:
                logger.error("Automated login failed: " + str(e))
                browser.quit()
                if not browser_visible:
                    display.stop()
                sys.exit(1)
        else:
            print("Exiting due to failed manual login.")
            browser.quit()
            if not browser_visible:
                display.stop()
            sys.exit(1)

    # Grab cookies from the session
    cookies = {}
    for cookie in browser.get_cookies():
        cookies[cookie['name']] = cookie['value']

    browser.quit()
    if not browser_visible:
        display.stop()

    return cookies, csrf_token, custid


"""
NOTE: This function is not used currently, because the download URL can be
constructed without this additional request. This might change in the future,
so I'm keeping this here just in case.

def get_download_url(user_agent, cookies, csrf_token, asin, device_id):
    logger.info("Getting download URL for " + asin)
    data_json = {
        'param':{
            'DownloadViaUSB':{
                'contentName':asin,
                'encryptedDeviceAccountId':device_id, # device['deviceAccountId']
                'originType':'Purchase'
            }
        }
    }    

    r = requests.post('https://www.amazon.com/hz/mycd/ajax',
        data={'data':json.dumps(data_json), 'csrfToken':csrf_token},
        headers=user_agent, cookies=cookies)
    rr = json.loads(r.text)["DownloadViaUSB"]
    return rr["URL"] if rr["success"] else None
"""


def get_devices(user_agent, cookies, csrf_token):
    logger.info("Getting device list")
    data_json = {'param': {'GetDevices': {}}}

    r = requests.post('https://www.amazon.com/hz/mycd/ajax',
                      data={'data': json.dumps(data_json), 'csrfToken': csrf_token},
                      headers=user_agent, cookies=cookies)
    devices = json.loads(r.text)["GetDevices"]["devices"]

    return [device for device in devices if 'deviceSerialNumber' in device]


def get_asins(user_agent, cookies, csrf_token):
    logger.info("Getting e-book list")
    startIndex = 0
    batchSize = 100
    data_json = {
        'param': {
            'OwnershipData': {
                'sortOrder': 'DESCENDING',
                'sortIndex': 'DATE',
                'startIndex': startIndex,
                'batchSize': batchSize,
                'contentType': 'Ebook',
                'itemStatus': ['Active'],
                'originType': ['Purchase'],
            }
        }
    }

    # NOTE: This loop could be replaced with only one request, since the
    # response tells us how many items are there ('numberOfItems'). I guess that
    # number will never be high enough to cause problems, but I want to be on
    # the safe side, hence the download in batches approach.
    asins = []
    while True:
        r = requests.post('https://www.amazon.com/hz/mycd/ajax',
                          data={'data': json.dumps(data_json), 'csrfToken': csrf_token},
                          headers=user_agent, cookies=cookies)
        rr = json.loads(r.text)
        asins += [book['asin'] for book in rr['OwnershipData']['items']]

        if rr['OwnershipData']['hasMoreItems']:
            startIndex += batchSize
            data_json['param']['OwnershipData']['startIndex'] = startIndex
        else:
            break

    return asins


def download_books(user_agent, cookies, device, asins, custid, directory):
    logger.info("Downloading {} books".format(len(asins)))
    cdn_url = 'https://cde-ta-g7g.amazon.com/FionaCDEServiceEngine/FSDownloadContent'
    cdn_params = 'type=EBOK&key={}&fsn={}&device_type={}&customerId={}&authPool=Amazon'

    for asin in asins:
        try:
            params = cdn_params.format(asin, device['deviceSerialNumber'], device['deviceType'], custid)
            r = requests.get(cdn_url, params=params, headers=user_agent, cookies=cookies, stream=True)
            
            # Extract the filename from the Content-Disposition header
            content_disp = r.headers.get('Content-Disposition', '')
            match = re.findall("filename\\*=UTF-8''(.+)", content_disp)
            if not match:
                logger.error("Filename not found in headers for ASIN: " + asin)
                continue
            name = match[0]
            name = urllib.parse.unquote(name)
            name = name.replace('/', '_')
            
            # Build the full path and check if file exists
            file_path = os.path.join(directory, name)
            if os.path.exists(file_path):
                logger.info("Skipping {}: file already exists ({})".format(asin, name))
                continue

            # Download and save the file
            with open(file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=512):
                    f.write(chunk)
            logger.info('Downloaded ' + asin + ': ' + name)
        except Exception as e:
            logger.debug(e)
            logger.error('Failed to download ' + asin)


def main():
    parser = ArgumentParser(description="Amazon e-book downloader.")
    # Set verbose to default True
    parser.add_argument("--verbose", help="show info messages", action="store_true", default=True)
    # Use --hidebrowser to run headless; by default, the browser is visible for manual login.
    parser.add_argument("--hidebrowser", help="run browser in headless mode", action="store_true")
    parser.add_argument("--outputdir", help="download directory (default: books)", default=None)
    parser.add_argument("--proxy", help="HTTP proxy server", default=None)
    parser.add_argument("--asin", help="list of ASINs to download", nargs='*')
    parser.add_argument("--logfile", help="name of file to write log to", default=None)
    args = parser.parse_args()

    # Verbose logging is now enabled by default
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(levelname)s]\t%(asctime)s %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if args.logfile:
        handlerLog = logging.FileHandler(args.logfile)
        logger.addHandler(handlerLog)

    # Determine output directory:
    if args.outputdir:
        output_dir = args.outputdir
    else:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        output_dir = os.path.join(script_dir, "books")
    if os.path.isfile(output_dir):
        logger.error("Output directory is a file!")
        return -1
    elif not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    browser_visible = not args.hidebrowser

    # No credentials are prompted for initially. Manual login is the default.
    cookies, csrf_token, custid = create_session(
        browser_visible=browser_visible, proxy=args.proxy
    )
    
    if not args.asin:
        asins = get_asins(user_agent, cookies, csrf_token)
    else:
        asins = args.asin

    devices = get_devices(user_agent, cookies, csrf_token)
    print("Please choose which device you want to download your e-books to!")
    for i in range(len(devices)):
        print(" " + str(i) + ". " + devices[i]['deviceAccountName'])
    while True:
        try:
            choice = int(input("Device #: "))
        except:
            logger.error("Not a number!")
        if choice in range(len(devices)):
            break

    download_books(user_agent, cookies, devices[choice], asins, custid, output_dir)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")