# Kindle Bulk Backup

Forked from https://github.com/sghctoma/bOOkp

This tool automates the process of downloading your Amazon Kindle e-books for personal backup. It works by logging into your Amazon account, retrieving your e-book and device lists, and then downloading the books for a selected device. After downloading, you can use [ApprenticeHarper's DeDRM tools](https://github.com/apprenticeharper/DeDRM_tools) with the provided device serial number to remove DRM.

> **Important:**  
> This tool is intended only for personal backups of content you legally own. Use it responsibly and in accordance with applicable laws.

## Features

- **Manual Login (Default):**  
  Opens a visible browser window for you to log in manually (including MFA if required).

- **Automated Login Fallback:**  
  If manual login fails, the script will prompt you to attempt an automated login using backup credentials.

- **Device Selection:**  
  After logging in, the script retrieves your registered Kindle devices. You choose one from which your e-books will be downloaded.

- **Duplicate Skipping:**  
  Files that already exist in the output directory are skipped.

## Prerequisites

- **Python 3.x**

- **Google Chrome Browser**

- **ChromeDriver:**  
  You must install ChromeDriver (matching your installed version of Chrome) and ensure it is available in your system's PATH.  
  - Download ChromeDriver from: [https://chromedriver.chromium.org/downloads](https://chromedriver.chromium.org/downloads)  
  - On macOS, you can install it via Homebrew (if available) or manually place the binary in a folder in your PATH.

- **Other Python Dependencies:**  
  The following Python packages are required:
  - `requests`
  - `selenium`
  - `pyvirtualdisplay`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/dorkknight/kindlebulkbackup.git
   cd kindlebackup

2. Create and Activate a Virtual Environment (Optional but Recommended):

python3 -m venv myenv
source myenv/bin/activate  # On Windows: myenv\Scripts\activate

3. Install Python Dependencies:

pip install -r requirements.txt

4. Install ChromeDriver:

Ensure that ChromeDriver is installed and available in your system's PATH.

Download ChromeDriver

For macOS users, if Homebrew provides a compatible version, you can try:

brew install --cask chromedriver

Otherwise, download the correct version manually and place it in a directory included in your PATH.

## Usage

By default, the script uses manual login via a visible browser window.

Basic Usage (Manual Login)

Simply run the script without any credentials. 

It will open a browser for you to log in manually:
python3 kindlebackup.py --outputdir ./books

When you run the script:
Manual Login:
The browser will open
Log in manually (including MFA, if required) and then return to the terminal and press Enter.
