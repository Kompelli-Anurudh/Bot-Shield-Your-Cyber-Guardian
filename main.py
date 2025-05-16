from pyrogram import Client, filters
from pyrogram.errors import FloodWait
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import os
import sys
import logging
import time
import asyncio
import json

# Add the directory containing your script to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Increase timeout for Pyrogram operations
Client.TIMEOUT = 60  # Set timeout to 60 seconds

# Custom retry decorator
def retry_on_flood(max_retries=3):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except FloodWait as e:
                    if attempt == max_retries - 1:
                        raise
                    await asyncio.sleep(e.value)
        return wrapper
    return decorator

# Initialize the bot with your API ID, API Hash, and Bot Token
app = Client(
    "my_virus_total_bot",
    api_id=########,
    api_hash='##############################',
    bot_token='###########################################'
)

VIRUS_TOTAL_API_KEY = '######################################################'
VIRUS_TOTAL_URL_API = 'https://www.virustotal.com/vtapi/v2/url/report'
VIRUS_TOTAL_FILE_API = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUS_TOTAL_REPORT_API = 'https://www.virustotal.com/vtapi/v2/file/report'

def check_url_virus_total(url):
    params = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': url}
    try:
        response = requests.get(VIRUS_TOTAL_URL_API, params=params)
        response.raise_for_status()
        result = response.json()
        
        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            report = f"URL scan results:\nDetections: {positives}/{total}\n"
            report += " Warning: The URL is potentially malicious." if positives > 0 else " The URL appears to be safe."
            return report
        else:
            return "URL not found in VirusTotal database."
    except requests.exceptions.RequestException as e:
        return f"Error occurred while scanning URL: {e}"

def scan_file_virus_total(file_path):
    params = {'apikey': VIRUS_TOTAL_API_KEY}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    try:
        response = requests.post(VIRUS_TOTAL_FILE_API, files=files, params=params)
        response.raise_for_status()
        result = response.json()
        return result['scan_id']
    except requests.exceptions.RequestException as e:
        return f"Error occurred during file upload: {e}"

def wait_for_scan_completion(scan_id, max_retries=10, initial_delay=5, max_delay=60):
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            response = requests.get(VIRUS_TOTAL_REPORT_API, params={'apikey': VIRUS_TOTAL_API_KEY, 'resource': scan_id})
            response.raise_for_status()
            result = response.json()
            if result.get('response_code') == 1:
                return result
            logger.info(f"Scan not complete, retrying in {delay} seconds...")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # Exponential backoff
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logger.error(f"Error while waiting for scan completion: {e}")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)
    return None

@app.on_message(filters.text & filters.private)
async def handle_text(client, message):
    url = message.text
    report = check_url_virus_total(url)
    await message.reply_text(report)

@app.on_message(filters.document | filters.photo | filters.video | filters.audio)
@retry_on_flood()
async def handle_document(client, message):
    try:
        if message.photo:
            file_obj = message.photo.file_id
            file_name = f"photo_{message.photo.file_unique_id}.jpg"
        elif message.document:
            file_obj = message.document.file_id
            file_name = message.document.file_name
        elif message.video:
            file_obj = message.video.file_id
            file_name = f"video_{message.video.file_unique_id}.mp4"
        elif message.audio:
            file_obj = message.audio.file_id
            file_name = message.audio.file_name or f"audio_{message.audio.file_unique_id}.mp3"
        else:
            await message.reply_text("Unsupported file type.")
            return

        file_size = getattr(message.document or message.photo or message.video or message.audio, 'file_size', 0)
        if file_size > 32 * 1024 * 1024:  # 32 MB limit
            await message.reply_text("File is too large. Maximum size is 32 MB.")
            return

        await message.reply_text("Downloading and scanning the file. This may take a moment...")
        file_path = await client.download_media(file_obj, file_name=file_name)
        logger.info(f"File downloaded to {file_path}")

        scan_id = scan_file_virus_total(file_path)
        logger.info(f"Scan ID received: {scan_id}")

        if isinstance(scan_id, str) and scan_id.startswith("Error"):
            await message.reply_text(scan_id)
        else:
            await message.reply_text("File uploaded for scanning. Getting the report...")
            result = wait_for_scan_completion(scan_id)
            if result:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                report = f"Detections: {positives}/{total}\n"
                report += " Warning: The file is potentially malicious." if positives > 0 else " The file appears to be safe."
            else:
                report = "Scan not completed within the expected time. Please try again later."
            logger.info(f"Scan report: {report}")
            await message.reply_text(report)

            # Clean up the downloaded file
            try:
                os.remove(file_path)
                logger.info(f"File {file_path} removed")
            except Exception as e:
                logger.error(f"Error removing file {file_path}: {e}")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        await message.reply_text(f"An error occurred: {str(e)}")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Bot is running')

def run_http_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, Handler)
    httpd.serve_forever()

if __name__ == '__main__':
    server_thread = threading.Thread(target=run_http_server)
    server_thread.start()
    app.run()
