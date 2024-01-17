from flask import Flask, render_template,  jsonify, send_file, request, abort, flash, redirect, session, url_for
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import psutil
import logging
import pyrebase
import psutil
import logging
from flask import send_file
from threading import Thread
from collections import deque
from fpdf import FPDF
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime, timedelta
import os
import re
import json
import matplotlib.pyplot as plt
from scapy.layers.inet import TCP, IP
import threading
from firebase_admin import auth





app = Flask(__name__)

sniffing_enabled = True
max_packet_count = 1000
packets = deque(maxlen=max_packet_count)
logging.basicConfig(level=logging.INFO)

sniffing_thread = None



alerts = []


############ FIREBASE #################
# authentication
config = {
    "apiKey": "AIzaSyAUpiYs3CWGwwq49EgjWqv3vhkuHk7AaQQ",
    "authDomain": "netsnif-c443d.firebaseapp.com",
    "projectId": "netsnif-c443d",
    "storageBucket": "netsnif-c443d.appspot.com",
    "messagingSenderId": "948195785160",
    "appId": "1:948195785160:web:cdc43a0824730d7306a8fd",
    'databaseURL': 'https://netsnif-c443d-default-rtdb.asia-southeast1.firebasedatabase.app/'

}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

db = firebase.database()
person = {"is_logged_in": False, "name": "", "email": "", "uid": ""}
app.secret_key = 'secret_key'


#########################################################

#..
storage_path = "packet_history"
current_file_path = None
initialized = False
PACKET_HISTORY_DAYS = 7
packets_history = deque(maxlen=max_packet_count)



# Function to initialize packet history storage
def initialize_packet_history():
    global packets_history
    packets_history = load_packets_from_files()

# Function to store a packet in the history file
def store_packet_in_history(packet_info):
    with open(current_file_path, 'a') as file:
        json.dump(packet_info, file)
        file.write('\n')

# Function to load packets from history files
def load_packets_from_files():
    loaded_packets = deque(maxlen=max_packet_count)

    # Load packets from the current file
    if current_file_path and os.path.exists(current_file_path):
        with open(current_file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                packet_info = json.loads(line)
                loaded_packets.append(packet_info)

    return loaded_packets




#................................................................

def initialize_storage():
    if not os.path.exists(storage_path):
        os.makedirs(storage_path)

def create_new_file():
    global current_file_path
    current_file_path = os.path.join(storage_path, f"packets_{datetime.now().strftime('%Y%m%d')}.json")
    with open(current_file_path, 'w') as file:
        pass

def save_packet_to_file(packet_info):
    with open(current_file_path, 'a') as file:
        json.dump(packet_info, file)
        file.write('\n')

def load_packets_from_files():
    loaded_packets = deque(maxlen=max_packet_count)

    # Load packets from the current file
    if current_file_path and os.path.exists(current_file_path):
        with open(current_file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                packet_info = json.loads(line)
                loaded_packets.append(packet_info)

    return loaded_packets

def initialize_app():
    initialize_storage()
    create_new_file()
    global packets
    packets = load_packets_from_files()

initialize_app()

#..

def is_ipv4(addr):
    try:
        parts = addr.split(".")
        return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
    except ValueError:
        return False


def handle_alert(alert_data):
    global alerts
    # Check for duplicate alerts before adding
    if alert_data not in alerts:
        alerts.append(alert_data)







#................................................................


def packet_handler(packet):
    global sniffing_enabled
    try:
        if sniffing_enabled and packet.haslayer(IP):
            summary = packet.summary()
            protocol = packet[IP].proto

            packet_info = {
                "summary": summary,
                "length": len(packet),
                "protocol": protocol,
                "srcPort": packet[IP].sport,
                "dstPort": packet[IP].dport,
                "source": packet[IP].src,
                "destination": packet[IP].dst,
                "timestamp": datetime.fromtimestamp(packet.time).strftime('%d-%m-%Y  %H:%M:%S'),
                "packet_data": str(packet)  # Include the packet data
            }
                 # Check for specific DDoS attacks
            if detect_ddos(packet_info):
                alert_data = {
                    "alert_type": "DDoS Attack",
                    "reason": "Potential TCP-based DDoS Attack",
                    "packet_info": packet_info,
                    "severity": "Low",
                    "status": "Active"
                }
                handle_alert(alert_data)
                
                handle_alert(alert_data)
                # DNS Spoofing Detection Logic
                if DNS in packet and isinstance(packet[DNS].an, DNS.RR):
                    alert_data = {
                        "alert_type": "DNS Spoofing",
                        "packet_info": packet_info,
                        "severity": "moderate",
                        "status": "Active"
                    }
                    handle_alert(alert_data)

                # Spear Phishing Detection Logic
                if IP in packet and TCP in packet:
                    if 'HTTP' in packet and Raw in packet:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                        malicious_url = 'testphp.vulnweb.com'
                        if malicious_url.lower() in payload:
                            alert_data = {
                                "alert_type": "Spear Phishing",
                                "reason": f"Detected malicious URL: {malicious_url}",
                                "packet_info": packet_info,
                                "severity": "High",
                                "status": "Active"
                            }
                            handle_alert(alert_data)

            # SQL Injection Detection Logic
                if sql_injection_detection(packet):
                     detected, score = sql_injection_detection(packet)
                     alert_data = {
                        "alert_type": "SQL Injection",
                        "packet_info": packet_info,
                        "severity": "High" ,
                        "status": "Active"
                    }
                handle_alert(alert_data)



            # Add detection logic for other attacks (XSS, Brute Force, Social Engineering, etc.)
            # Customize these conditions based on your requirements

          # XSS Detection Logic
            if xss_detection(packet):
                alert_data = {
                    "alert_type": "XSS",
                    "reason": "Detected XSS attack in packet",
                    "packet_info": packet_info,
                    "severity": "High",
                    "status": "Active"
                }
                handle_alert(alert_data)
            # Brute Force Detection Logic (Example: Detecting multiple failed login attempts)
            if brute_force_detection(packet):
                alert_data = {
                    "alert_type": "Brute Force",
                    "packet_info": packet_info,
                    "severity": "Low",
                    "status": "Active"
                }
                handle_alert(alert_data)

            # Social Engineering Detection Logic (Example: Detecting specific keywords in traffic)
            if social_engineering_detection(packet):
                alert_data = {
                    "alert_type": "Social Engineering",
                    "packet_info": packet_info,
                    "severity": "Moderate",
                    "status": "Active"
                }
                handle_alert(alert_data)

            packets_history.append(packet_info)
            store_packet_in_history(packet_info)

            packets.append(packet_info)
            save_packet_to_file(packet_info)
            packets.append(packet_info)
            return packet_info

    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def xss_detection(packet):
    try:
        if "Raw" in packet:
            payload = packet["Raw"].load.decode('utf-8', errors='ignore').lower()

            # XSS patterns
            xss_patterns = [
                r'<script\b[^>]*>',
                r'onerror\s*=\s*["\']?[^"\'>]*["\']?',
                r'javascript:',
                # Add more patterns as needed based on your specific use case
            ]

            # Check each pattern
            for pattern in xss_patterns:
                if re.search(pattern, payload):
                    return True  # XSS pattern detected

            return False

        return False
    except Exception as e:
        logging.error(f"Error in xss_detection: {e}")
        return False


# # DDoS detection thread
# def ddos_detection_thread():
#     sniff(iface="your_network_interface", prn=packet_handler, stop_filter=lambda x: not sniffing_enabled, count=0)

# # Start DDoS detection thread
# ddos_thread = threading.Thread(target=ddos_detection_thread)
# ddos_thread.start()

def brute_force_detection(packet):
    try:
        # Assuming 'packet_info' is a key in the 'packet' dictionary
        packet_info = packet.get("packet_info", {})
        
        # Implement more sophisticated brute force detection logic
        if "TCP" in packet and packet["TCP"].dport == 22:  # Assuming SSH traffic
            # Add conditions to detect multiple failed login attempts
            if "Failed password" in packet["Raw"].load.decode('utf-8', errors='ignore'):
                # Consider tracking failed attempts over time
                # (e.g., using a data structure to store timestamps of failed attempts)

                # Implement a mechanism to track failed login attempts
                if "source_ip" not in session:
                    session["source_ip"] = packet["IP"].src
                    session["failed_attempts"] = 1
                else:
                    if session["source_ip"] == packet["IP"].src:
                        session["failed_attempts"] += 1
                    else:
                        # Reset attempts if the source IP changes
                        session["source_ip"] = packet["IP"].src
                        session["failed_attempts"] = 1

                # Set a threshold for failed attempts (adjust as needed)
                failed_attempts_threshold = 3

                if session["failed_attempts"] > failed_attempts_threshold:
                    # Trigger alert or take action for detected brute force attempt
                    alert_data = {
                        "alert_type": "Brute Force",
                        "packet_info": packet_info,
                        "severity": "High",
                        "status": "Active"
                    }
                    handle_alert(alert_data)

                    return True  # Brute force pattern detected

        return False
    except Exception as e:
        logging.error(f"Error in brute_force_detection: {e}")
        return False


def social_engineering_detection(packet):
    # Implement more sophisticated social engineering detection logic
    if Raw in packet and TCP in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        # Add conditions to detect specific keywords related to social engineering
        social_engineering_keywords = ["password", "login", "phishing"]
        if any(keyword in payload.lower() for keyword in social_engineering_keywords):
            return True
    return False

def detect_ddos(packet_info):
    thresholds = {
        "length": 1400,  # Adjust based on your network capacity
        "request_rate": 1000,  # Adjust based on normal request rates
        "high_application_layer": 2000,  # Adjust based on normal application-layer traffic
        "extended_duration": 1800,  # 30 minutes, adjust based on expected service outage duration
        "variability": 3  # Number of different attack patterns or vectors to detect variability
    }

    # Check general thresholds
    for key, threshold in thresholds.items():
        if packet_info.get(key, 0) > threshold:
            return True

    # Additional checks for specific attack types
    if packet_info.get("source_ip_spoofing") or \
       packet_info.get("fragmented_packets") or \
       packet_info.get("protocol_exploitation") or \
       packet_info.get("amplification_techniques") or \
       packet_info.get("botnet_involvement"):
        return True

    # Check for specific conditions that may indicate an attack

    # Check for large number of SYN packets (indicative of SYN flood attack)
    if packet_info.get("protocol") == "TCP" and packet_info.get("flags") == "S" and packet_info.get("length", 0) == 0:
        return True

    # Check for abnormal DNS query patterns
    if packet_info.get("protocol") == "DNS" and packet_info.get("dns_query_count", 0) > 50:
        return True

    # Check for abnormal HTTP response codes
    if packet_info.get("protocol") == "HTTP" and packet_info.get("http_response_codes", {}).get("4xx", 0) > 10:
        return True

    # Add more specific checks as needed

    return False




def packet_capture_thread(selected_interface):
    sniff(iface=selected_interface, prn=packet_handler,
          stop_filter=lambda x: not sniffing_enabled, count=0)







def sql_injection_detection(packet):
    try:
        if "Raw" in packet and "TCP" in packet:
            payload = packet["Raw"].load.decode('utf-8', errors='ignore')

            # SQL injection patterns
            sql_injection_patterns = [
                r'\b(?:union|select|insert|update|delete|drop|alter|create|truncate|grant|revoke|backup|restore)\b',
                r'\b(?:and|or)\b\s*(?:[\d\s=]+|true|false|null)',
                r'\b(?:exec|execute)\(',
                r'\b(?:declare|cast|convert|nvarchar|xp_cmdshell|sp_executesql|createprocedure)\b',
                r'\b(?:@@|\bversion\b|\bdatabase\b|\buser\b|\bhost_name\b)\b',
                r'\b(?:escalation|escalade|pillow)\b',  # Keywords related to Eskelin injection
                # Add more patterns as needed based on your specific use case
            ]

            # Check each pattern and calculate the score
            score = sum(1 for pattern in sql_injection_patterns if re.search(pattern, payload, re.IGNORECASE))

            # Set a threshold for the score (adjust as needed)
            detection_threshold = 2

            # Return the detection status and score
            return score > detection_threshold, score

        return False, 0
    except Exception as e:
        logging.error(f"Error in sql_injection_detection: {e}")
        return False, 0






############ LOGIN ################


@app.route('/', methods=["GET", "POST"])
def index():
    if request.method == "POST":
        result = request.form
        email = result.get("email")
        password = result.get("password")

        print(email, password)
        try:
            # Try signing in the user with the given information
            user = auth.sign_in_with_email_and_password(email, password)

            print(user)
            # Insert the user data in the global person
            session["is_logged_in"] = True
            session["email"] = user["email"] 
            session["uid"] = user["localId"]
            # global person
            # person["is_logged_in"] = True
            # person["email"] = user["email"]
            # person["uid"] = user["localId"]
            # Get the name of the user
            # data = db.child("users").get()
            # person["name"] = data.val()[person["uid"]]["name"]

            return redirect(url_for('dashboard'))

        except:
            flash('Login failed, Please try again.')
            return redirect(url_for('index'))

    if person['is_logged_in']:
        return redirect(url_for('dashboard'))

    return render_template('login.html')


 ############ REGISTRATION ##################



@app.route('/registration', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        result = request.form
        email = result.get("email")
        password = result.get("password")
        name = result.get("name")

        try:
            # Try creating the user account using the provided data
            auth.create_user_with_email_and_password(email, password)

            # Login the user
            user = auth.sign_in_with_email_and_password(email, password)

           
            session["is_logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]

            # Append data to the Firebase Realtime Database
            data = {"name": name, "email": email}
            db.child("users").child(person["uid"]).set(data)

            flash('Account created successfully. You are now logged in!')

            # Go to the dashboard
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            flash('Registration failed. Please try again.')
            return redirect(url_for('register'))
    else:
        if session.get('is_logged_in'):
            return redirect(url_for('dashboard'))
        else:
            return render_template('registration.html')




@app.route('/dashboard')
def dashboard():
    if session.get("is_logged_in"):
        return render_template('index.html', email=person["email"])
    else:
        return redirect(url_for('index'))


###### LOGOUT#####

@app.route('/logout')
def logout():
   
    session.clear()
    # auth.signout()
    return redirect('/')


@app.route('/packetcapture')
def capture():
    return render_template('packet_capture.html')


@app.route('/alert')
def alert():
    return render_template('alert.html', alerts=alerts)


@app.route('/history')
def history():
    return render_template('history.html')


from flask import jsonify

@app.route('/get_alerts_count')
def get_alerts_count():
    # Count alerts by severity
    counts = {"High": 0, "Moderate": 0, "Low": 0, "Unknown": 0}

    for alert in alerts:
        severity = alert.get("severity", "Unknown")  # Ensure severity key exists
        if severity in counts:
            counts[severity] += 1
        else:
            counts["Unknown"] += 1

    print(counts)  # Add this line to check counts in your server logs

    return jsonify(counts=counts)



@app.route('/toggle_sniffing')
def toggle_sniffing():
    global sniffing_enabled, sniffing_thread
    sniffing_enabled = not sniffing_enabled
    if sniffing_enabled and sniffing_thread is None:
        selected_interface = request.args.get('interface')
        sniffing_thread = Thread(
            target=packet_capture_thread, args=(selected_interface,))
        sniffing_thread.start()
    return jsonify(enabled=sniffing_enabled)


def process_packet(packet):
    packet_info = packet_handler(packet)
    if packet_info:
        packets.append(packet_info)


@app.route('/start_sniffing')
def start_sniffing():
    selected_interface = request.args.get('interface')
    packets.clear()
    sniff(iface=selected_interface, prn=process_packet,
          count=0)  # count=0 means sniff indefinitely
    return


@app.route('/get_interfaces')
def get_interfaces():
    try:
        interfaces = psutil.net_if_addrs().keys()
        return jsonify(interfaces=list(interfaces))
    except Exception as e:
        logging.error(f"Error retrieving network interfaces: {e}")
        return jsonify(error="Error retrieving network interfaces"), 500

    
def save_json_to_file(data, filename):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=2)


@app.route('/get_packets')
def get_packets():
    # Get the list of packets
    packet_list = list(packets)

    # Save the packets to a JSON file
    save_json_to_file(packet_list, 'packets.json')

    # Return the packets as JSON response
    return jsonify(packets=packet_list)

@app.route('/get_packets_json')
def get_packets_json():
    # Read the saved JSON file
    with open('packets.json', 'r') as json_file:
        json_data = json.load(json_file)

    # Return the JSON data as a response
    return jsonify(packets=json_data)

@app.route('/save_log')
def save_log():
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    pdf_file_path = os.path.join(
        os.getcwd(), f"captured_packets_{timestamp}.pdf")
    # Pass 'packets' to the generate_pdf function
    generate_pdf(pdf_file_path, packets)
    return send_file(pdf_file_path, as_attachment=True)



########### dashboard packet count ##############

def count_packets_in_interval(packet_list, interval_seconds=5):
    packet_counts = {}

    packets_copy=list(packet_list)

    for packet in packets_copy:
        timestamp = datetime.strptime(packet["timestamp"], '%d-%m-%Y %H:%M:%S')
        
        # Calculate the start of the interval
        interval_start = timestamp - timedelta(seconds=timestamp.second % interval_seconds,
                                               microseconds=timestamp.microsecond)
        
        # Format the rounded timestamp
        formatted_interval_start = interval_start.strftime('%d-%m-%Y %H:%M:%S')

        # Increment the packet count for the interval
        packet_counts[formatted_interval_start] = packet_counts.get(formatted_interval_start, 0) + 1

    return packet_counts

@app.route('/packet_count_chart_data')
def packet_count_chart_data():
    interval_packet_counts = count_packets_in_interval(packets, interval_seconds=5)
    return jsonify(packet_counts=interval_packet_counts)

@app.route('/get_packet_counts_by_timestamp')
def get_packet_counts_by_timestamp():
    packet_counts = count_packets_by_timestamp(packets)
    return jsonify(packet_counts=packet_counts)

def count_packets_by_timestamp(packet_list):
    packet_counts = {}

    for packet in packet_list:
        timestamp = datetime.strptime(packet["timestamp"], '%d-%m-%Y %H:%M:%S')
        # Round down the timestamp to the nearest 2 hours
        rounded_timestamp = timestamp - timedelta(minutes=timestamp.minute % 120,
                                                  seconds=timestamp.second,
                                                  microseconds=timestamp.microsecond)
        # Format the rounded timestamp
        formatted_timestamp = rounded_timestamp.strftime('%d-%m-%Y %H:%M:%S')

        packet_counts[formatted_timestamp] = packet_counts.get(formatted_timestamp, 0) + 1

    return packet_counts


############# dashboard packet count#########

def generate_pdf(file_path, packets):
    doc = SimpleDocTemplate(file_path, pagesize=letter)

    elements = []

    # Define table data and style
    data = [["Summary", "Length", "Source Port",
             "Source IP", "Destination IP", "Timestamp"]]
    for packet in packets:
        data.append([
            Paragraph(packet["summary"], getSampleStyleSheet()['BodyText']),
            Paragraph(str(packet["length"]), getSampleStyleSheet()['BodyText']),
            Paragraph(str(packet["srcPort"]), getSampleStyleSheet()['BodyText']),
            Paragraph(packet["source"], getSampleStyleSheet()['BodyText']),
            Paragraph(packet["destination"], getSampleStyleSheet()['BodyText']),
            Paragraph(packet["timestamp"], getSampleStyleSheet()['BodyText'])
        ])

    body_text_style = getSampleStyleSheet()['BodyText']
    body_text_style.fontName = 'Courier'  # Set font family if needed
    body_text_style.fontSize = 3  # Set the desired font size
    body_text_style.leftIndent = 20

    table = Table(data, colWidths=[280, 40, 67, 75, 80, 90], rowHeights=40)
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.black),
    ])

    table.setStyle(style)
    elements.append(table)

    # Build and save the PDF
    doc.build(elements)

    

@app.route('/get_realtime_alerts_count')
def get_realtime_alerts_count():
    # Count alerts by severity
    counts = {"High": 0, "Moderate": 0, "Low": 0, "Unknown": 0}

    for alert in alerts:
        severity = alert.get("severity", "Unknown")  # Ensure severity key exists

        # Increment the count based on severity
        if severity == "High":
            counts["High"] += 1
        elif severity == "Moderate":
            counts["Moderate"] += 1
        elif severity == "Low":
            counts["Low"] += 1
        else:
            counts["Unknown"] += 1

    return jsonify(counts=counts)

if __name__ == '__main__':
    app.run(port=5018, debug=True)