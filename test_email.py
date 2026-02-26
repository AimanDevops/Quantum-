import smtplib
from email.mime.text import MIMEText

# --- PUT YOUR DETAILS HERE ---
SENDER_EMAIL = "your_real_email@gmail.com"
SENDER_PASSWORD = "abcd efgh ijkl mnop"  # Your 16-letter App Password
TARGET_EMAIL = "your_real_email@gmail.com" # Send to yourself

try:
    print("1. Connecting to Gmail...")
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    
    print("2. Logging in...")
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    
    print("3. Sending test message...")
    msg = MIMEText("If you see this, your App Password works!")
    msg['Subject'] = "QSAM Test Email"
    msg['From'] = SENDER_EMAIL
    msg['To'] = TARGET_EMAIL
    
    server.send_message(msg)
    server.quit()
    print("✅ SUCCESS! Email sent. Check your inbox.")

except Exception as e:
    print("\n❌ FAILED. Here is the error:")
    print(e)
    print("\nFIX:")
    print("- If error is 'Username and Password not accepted': Your App Password is wrong.")
    print("- If error is 'Please log in via your web browser': You are using your normal password (STOP). Use an App Password.")