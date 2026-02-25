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

app = Flask(__name__)
app.secret_key = "super_secret_key"

# --- CONFIGURATION ---
ENABLE_EMAIL = True
SENDER_EMAIL = "nahinnasir14@gmail.com"   

SENDER_PASSWORD = "rggo bijc tqfd vzck"

failed_attempts = {}

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
    
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users VALUES ('admin', 'admin123', 'Admin', 'admin@umt.edu.pk')")
    conn.commit()
    conn.close()

init_db()

# --- GLOBAL FACE DETECTOR ---
# We load this once to use it everywhere
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# --- ROUTES ---
@app.route('/')
def home(): return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('home'))
    if session['role'] == 'Admin': return redirect(url_for('admin_panel'))
    
    my_grades = [g for g in DUMMY_GRADES if g[0] == session['user']]

    return render_template('dashboard.html', 
                         username=session['user'], 
                         role=session['role'], 
                         grades=my_grades,
                         ip=socket.gethostbyname(socket.gethostname()))

@app.route('/admin_panel')
def admin_panel():
    if 'user' not in session or session['role'] != 'Admin': return "Access Denied"
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    users = c.execute("SELECT * FROM users").fetchall()
    feedback = c.execute("SELECT * FROM feedback").fetchall()
    conn.close()
    return render_template('admin_panel.html', users=users, feedback=feedback, courses=DUMMY_COURSES, grades=DUMMY_GRADES)

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    data = request.json
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO feedback (student, teacher, rating, comment, date) VALUES (?, ?, ?, ?, ?)", 
                 (session['user'], data['teacher'], data['rating'], data['comment'], str(datetime.now().date())))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})

@app.route('/add_user', methods=['POST'])
def add_user():
    if session['role'] != 'Admin': return jsonify({'success': False})
    data = request.json
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (data['username'], data['password'], data['role'], data['email']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    u, p = data['username'], data['password']
    img_data = data.get('image', '').split(',')[1] if 'image' in data else None
    
    # 1. CRITICAL SECURITY CHECK: Is there a face in the login attempt?
    if not img_data:
        return jsonify({'success': False, 'message': 'Camera blocked or image missing.'})
        
    # Decode image to check for face
    img_bytes = base64.b64decode(img_data)
    nparr = np.frombuffer(img_bytes, np.uint8)
    img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.1, 4)

    # If NO face found in the specific login click photo -> REJECT
    if len(faces) == 0:
        return jsonify({'success': False, 'message': 'FACE CHECK FAILED: You must look at the camera to login.'})

    # 2. PROCEED TO DB CHECK
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (u,))
    user = c.fetchone()
    conn.close()

    if not user: return jsonify({'success': False, 'message': 'User not found'})

    if user[1] == p:
        session['user'] = u
        session['role'] = user[2]
        failed_attempts[u] = 0
        return jsonify({'success': True})
    else:
        failed_attempts[u] = failed_attempts.get(u, 0) + 1
        count = failed_attempts[u]
        msg = "Wrong Password"
        if count >= 3:
            msg = "Intruder Alert! Photo Sent."
            send_intruder_alert(user[3], img_data)
            failed_attempts[u] = 0
        return jsonify({'success': False, 'message': msg, 'attempts': count})

def send_intruder_alert(user_email, image_b64):
    if not ENABLE_EMAIL: return
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "🚨 SECURITY ALERT"
        msg['From'] = SENDER_EMAIL
        msg['To'] = user_email
        msg.attach(MIMEText("3 Failed Login Attempts detected.", 'plain'))
        if image_b64:
            msg.attach(MIMEImage(base64.b64decode(image_b64), name="intruder.jpg"))
        with smtplib.SMTP('smtp.gmail.com', 587) as s:
            s.starttls()
            s.login(SENDER_EMAIL, SENDER_PASSWORD)
            s.send_message(msg)
    except: pass

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/get_quantum_key')
def get_key(): return jsonify(generate_key(length=128))

@app.route('/detect_face', methods=['POST'])
def detect_face():
    data = request.json
    img_data = data['image'].split(',')[1]
    img_bytes = base64.b64decode(img_data)
    nparr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    faces = face_cascade.detectMultiScale(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), 1.1, 4)
    return jsonify({'face_detected': len(faces) > 0}) 

if __name__ == '__main__':
    app.run(debug=True)