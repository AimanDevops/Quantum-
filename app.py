from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import cv2
import base64
import numpy as np
import socket
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from datetime import datetime
from quantum.bb84 import generate_key

# Import AI modules
from sentiment_analyzer import SentimentAnalyzer, StudentRanker
from anomaly_detector import LoginBehaviorAnalyzer, RuleBasedDetector
from chatbot import StudentChatbot, ChatHistory

app = Flask(__name__)
app.secret_key = "super_secret_key"

# --- CONFIGURATION ---
ENABLE_EMAIL = True
SENDER_EMAIL = "nahinnasir14@gmail.com"   
SENDER_PASSWORD = "rggo bijc tqfd vzck"

failed_attempts = {}

# Initialize AI modules
sentiment_analyzer = SentimentAnalyzer()
student_ranker = StudentRanker()
anomaly_detector = LoginBehaviorAnalyzer()
anomaly_detector.init_db()
rule_detector = RuleBasedDetector()
chatbot = StudentChatbot()
chat_history = ChatHistory()

# --- DUMMY DATA ---
DUMMY_GRADES = [
    ("f2022376139", "CS305 - InfoSec", "Midterm Exam", "85/100", "A-"),
    ("f2022376139", "CS401 - FYP II", "Proposal Defense", "92/100", "A"),
    ("f2022376139", "MG101 - Ethics", "Quiz 1", "08/10", "B+"),
    ("testuser", "CS101", "Final", "40/100", "F")
]

DUMMY_COURSES = [
    ("CS401", "Final Year Project II", "Dr. Fatima Tariq", "Spring 2026"),
    ("CS305", "Information Security", "Mr. Zunnurain", "Spring 2026"),
    ("MG101", "Professional Practices", "Ms. Ayesha", "Spring 2026")
]

# --- DATABASE ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT, email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, student TEXT, teacher TEXT, rating INTEGER, comment TEXT, date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS grades (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id TEXT, course TEXT, assessment TEXT, score TEXT, grade TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS student_rankings (id INTEGER PRIMARY KEY AUTOINCREMENT, student TEXT UNIQUE, academic_score REAL, sentiment_score REAL, final_score REAL, rank_position INTEGER, sentiment_label TEXT, feedback_count INTEGER, last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users VALUES ('admin', 'admin123', 'Admin', 'admin@umt.edu.pk')")
    c.execute("SELECT COUNT(*) FROM grades")
    if c.fetchone()[0] == 0:
        for grade in DUMMY_GRADES:
            c.execute("INSERT INTO grades (student_id, course, assessment, score, grade) VALUES (?, ?, ?, ?, ?)", grade)
    conn.commit()
    conn.close()

init_db()

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# --- ROUTES ---

@app.route('/')
def home(): 
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session or not session.get('quantum_verified'):
        return redirect(url_for('home'))
    if session['role'] == 'Admin':
        return redirect(url_for('admin_panel'))
    my_grades = [g for g in DUMMY_GRADES if g[0] == session['user']]
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT rank_position, final_score, sentiment_label FROM student_rankings WHERE student = ?", (session['user'],))
    ranking = c.fetchone()
    conn.close()
    
    # FIX: Matching your filename dashboard_updated.html
    return render_template('dashboard_updated.html', username=session['user'], role=session['role'], grades=my_grades, ip=socket.gethostbyname(socket.gethostname()), ranking=ranking)

@app.route('/admin_panel')
def admin_panel():
    if 'user' not in session or session['role'] != 'Admin': 
        return "Access Denied"
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    users = c.execute("SELECT * FROM users").fetchall()
    feedback = c.execute("SELECT * FROM feedback").fetchall()
    rankings = c.execute("SELECT * FROM student_rankings ORDER BY rank_position").fetchall()
    alerts = c.execute("SELECT * FROM anomaly_alerts WHERE resolved = 0 ORDER BY alert_time DESC").fetchall()
    conn.close()
    
    # FIX: Matching your filename admin_panel_updated.html
    return render_template('admin_panel_updated.html', users=users, feedback=feedback, courses=DUMMY_COURSES, grades=DUMMY_GRADES, rankings=rankings, alerts=alerts)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    u, p = data['username'], data['password']
    img_data = data.get('image', '').split(',')[1] if 'image' in data else None
    ip_address = request.remote_addr or 'unknown'

    if not img_data:
        return jsonify({'success': False, 'message': 'Camera blocked or image missing.'})

    img_bytes = base64.b64decode(img_data)
    nparr = np.frombuffer(img_bytes, np.uint8)
    img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.1, 4)

    if len(faces) == 0:
        return jsonify({'success': False, 'message': 'FACE CHECK FAILED: You must look at the camera to login.'})

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (u,))
    user = c.fetchone()
    conn.close()

    if not user: 
        return jsonify({'success': False, 'message': 'User not found'})

    if user[1] == p:
        anomaly_detector.log_login_attempt(u, ip_address, True, True)
        qkey = generate_key(length=64)['key']
        session['quantum_key'] = qkey
        session['quantum_verified'] = False
        session['user'] = u
        session['role'] = user[2]
        failed_attempts[u] = 0
        return jsonify({'success': True, 'quantum_key': qkey})
    else:
        failed_attempts[u] = failed_attempts.get(u, 0) + 1
        count = failed_attempts[u]
        anomaly_detector.log_login_attempt(u, ip_address, False, len(faces) > 0)
        
        msg = "Wrong Password"
        if count >= 3:
            msg = "Intruder Alert! Photo and IP address sent to your email."
            # UPDATED: Sending ip_address to the alert function
            send_intruder_alert(user[3], img_data, ip_address) 
            failed_attempts[u] = 0
        return jsonify({'success': False, 'message': msg, 'attempts': count})

# --- ALERT SYSTEM WITH IP TRACKING ---
def send_intruder_alert(user_email, image_b64, ip_address):
    if not ENABLE_EMAIL: 
        return
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "URGENT: Intruder Alert Detected"
        msg['From'] = SENDER_EMAIL
        msg['To'] = user_email
        
        # Adding IP Address to the email body for Active Intrusion Defense
        body = f"A security breach attempt was detected on your account.\n\n" \
               f"Detected IP: {ip_address}\n" \
               f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n" \
               f"An image of the intruder is attached below."
        msg.attach(MIMEText(body, 'plain'))
        
        if image_b64:
            msg.attach(MIMEImage(base64.b64decode(image_b64), name="intruder.jpg"))
            
        with smtplib.SMTP('smtp.gmail.com', 587) as s:
            s.starttls()
            s.login(SENDER_EMAIL, SENDER_PASSWORD)
            s.send_message(msg)
    except Exception as e:
        print(f"Email error: {e}")

# ... (Keep remaining routes like /quantum_verify, /chatbot etc. as they were) ...

if __name__ == '__main__':
    app.run(debug=True)