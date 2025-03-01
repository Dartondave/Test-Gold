import time
import uuid
import random
import base64
import hmac
import hashlib
import re
import binascii
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def get_secret(url):
    try:
        # Set up headless Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")

        # Initialize WebDriver
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        content = driver.page_source
        driver.quit()

        # Search for the TAP_SECRET variable in the content
        match = re.search(r'TAP_SECRET\s*=\s*["\']([^"\']+)["\']', content)
        if not match:
            raise ValueError('TAP_SECRET variable not found.')

        # Extract the TAP_SECRET value
        tap_secret = match.group(1)

        # Decode the TAP_SECRET value
        secret_bytes = base64.b32decode(tap_secret, casefold=True)
        secret_hex = binascii.hexlify(secret_bytes).decode()
        return secret_hex
    except Exception as e:
        raise ValueError(f'Error fetching or decoding TAP_SECRET: {e}')

def generate_totp_in_base64(secret_hex, step=2, digits=6, algorithm=hashlib.sha1):
    secret_bytes = bytes.fromhex(secret_hex)
    time_counter = int(time.time() // step)
    time_counter_bytes = time_counter.to_bytes(8, byteorder="big")
    hmac_hash = hmac.new(secret_bytes, time_counter_bytes, algorithm).digest()
    offset = hmac_hash[-1] & 0x0F
    code_int = int.from_bytes(hmac_hash[offset:offset+4], byteorder="big") & 0x7FFFFFFF
    otp = code_int % (10 ** digits)
    otp_str = str(otp).zfill(digits)
    otp_base64 = base64.b64encode(otp_str.encode()).decode()
    return otp_base64

# URL containing the TAP_SECRET variable
SECRET_URL = 'https://telegram.geagle.online/assets/index-B2UGGrRc.js'

# Fetch the secret
try:
    secret_hex = get_secret(SECRET_URL)
except Exception as e:
    print(f"Error fetching secret: {e}")
    exit(1)

# Read tokens from file
try:
    with open('data.txt', 'r') as file:
        tokens = [line.strip() for line in file.readlines()]
except Exception as e:
    print(f"Error reading tokens from file: {e}")
    exit(1)

available_taps = 1000

# Main loop
while True:
    for token in tokens:
        print(f"\nProcessing token: {token}")
        for i in range(1):
            count = random.randint(510, 520)
            # Prepare headers and data
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.9',
                'authorization': f'Bearer {token}',
                'content-type': 'application/json',
                'origin': 'https://telegram.geagle.online',
                'referer': 'https://telegram.geagle.online/',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            }
            nonce = generate_totp_in_base64(secret_hex=secret_hex)
            data = {
                "available_taps": available_taps,
                "count": count,
                "timestamp": int(time.time()),
                "salt": str(uuid.uuid4()),
                "nonce": nonce,
            }
            # Send request using Selenium WebDriver
            driver = webdriver.Chrome(options=chrome_options)
            driver.get('https://gold-eagle-api.fly.dev/tap')
            # Implement form filling and submission using Selenium
            # ...
            driver.quit()

            delay = random.uniform(2, 5)
            print(f"Calculated delay: {delay:.2f} seconds")
            time.sleep(delay)

        print(f"Completed requests for token {token}.")

    sleep_time = random.uniform(8 * 60, 8.2 * 60)
    print(f"Sleeping for {sleep_time:.2f} seconds before processing next batch of tokens...")
    time.sleep(sleep_time)
