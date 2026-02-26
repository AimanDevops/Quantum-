"""
AI Anomaly Detection Module for Login Behavior Analysis
Detects unusual login patterns using machine learning (Isolation Forest)
"""

import sqlite3
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import pickle
import os

# Try to import sklearn, if not available use simple statistical method
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. Using statistical anomaly detection.")


class LoginBehaviorAnalyzer:
    """Analyzes login patterns to detect anomalies."""

    def __init__(self, db_path='users.db', model_path='anomaly_model.pkl'):
        self.db_path = db_path
        self.model_path = model_path
        self.model = None
        self.user_patterns = {}

    def init_db(self):
        """Create tables for storing login behavior data."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Login attempts table
        c.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                success BOOLEAN,
                face_detected BOOLEAN,
                is_anomaly BOOLEAN DEFAULT 0,
                anomaly_score REAL,
                location TEXT
            )
        ''')

        # Anomaly alerts table
        c.execute('''
            CREATE TABLE IF NOT EXISTS anomaly_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                description TEXT,
                severity TEXT,
                resolved BOOLEAN DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    def log_login_attempt(self, username, ip_address, success, face_detected, location=None):
        """Log a login attempt for analysis."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''
            INSERT INTO login_attempts (username, ip_address, success, face_detected, location)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, ip_address, success, face_detected, location))

        conn.commit()
        conn.close()

    def get_user_login_history(self, username, days=30):
        """Get login history for a specific user."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        since = datetime.now() - timedelta(days=days)

        c.execute('''
            SELECT timestamp, ip_address, success, face_detected
            FROM login_attempts
            WHERE username = ? AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (username, since))

        history = c.fetchall()
        conn.close()

        return history

    def extract_features(self, username, history):
        """Extract behavioral features from login history."""
        if not history:
            return None

        features = {}

        # Time-based features
        timestamps = [datetime.fromisoformat(str(h[0]).replace('Z', '+00:00')) for h in history]
        hours = [t.hour for t in timestamps]

        features['avg_hour'] = np.mean(hours) if hours else 12
        features['hour_std'] = np.std(hours) if len(hours) > 1 else 0
        features['login_count'] = len(history)

        # Success rate
        successes = [h[2] for h in history]
        features['success_rate'] = sum(successes) / len(successes) if successes else 0

        # Face detection rate
        faces = [h[3] for h in history]
        features['face_detection_rate'] = sum(faces) / len(faces) if faces else 0

        # IP diversity
        ips = set([h[1] for h in history])
        features['unique_ips'] = len(ips)

        # Time since last login (in hours)
        if timestamps:
            last_login = max(timestamps)
            hours_since = (datetime.now() - last_login).total_seconds() / 3600
            features['hours_since_last'] = hours_since
        else:
            features['hours_since_last'] = 999

        # Failed attempts in last 24 hours
        recent = datetime.now() - timedelta(hours=24)
        recent_failures = sum(1 for h in history 
                             if not h[2] and datetime.fromisoformat(str(h[0]).replace('Z', '+00:00')) > recent)
        features['recent_failures'] = recent_failures

        return features

    def features_to_vector(self, features):
        """Convert feature dict to numpy vector."""
        if not features:
            return np.zeros(8)

        return np.array([
            features['avg_hour'],
            features['hour_std'],
            features['login_count'],
            features['success_rate'],
            features['face_detection_rate'],
            features['unique_ips'],
            min(features['hours_since_last'], 168),  # Cap at 1 week
            features['recent_failures']
        ]).reshape(1, -1)

    def train_model(self):
        """Train anomaly detection model on historical data."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Get all users with login history
        c.execute("SELECT DISTINCT username FROM login_attempts")
        users = [row[0] for row in c.fetchall()]
        conn.close()

        if len(users) < 2:
            print("Not enough data to train model")
            return False

        # Extract features for all users
        X = []
        for user in users:
            history = self.get_user_login_history(user, days=90)
            features = self.extract_features(user, history)
            if features:
                X.append(self.features_to_vector(features)[0])

        if len(X) < 5:
            print("Not enough training samples")
            return False

        X = np.array(X)

        if SKLEARN_AVAILABLE:
            # Use Isolation Forest
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.model.fit(X)

            # Save model
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
        else:
            # Use statistical approach - store mean and std
            self.model = {
                'mean': np.mean(X, axis=0),
                'std': np.std(X, axis=0) + 1e-6
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)

        return True

    def load_model(self):
        """Load trained model."""
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            return True
        return False

    def detect_anomaly(self, username, ip_address, current_features=None):
        """Detect if current login is anomalous."""
        if not self.model:
            if not self.load_model():
                # Train new model if none exists
                self.train_model()

        if not current_features:
            history = self.get_user_login_history(username, days=30)
            current_features = self.extract_features(username, history)

        if not current_features:
            return {'is_anomaly': False, 'score': 0, 'reason': 'No history'}

        X = self.features_to_vector(current_features)

        if SKLEARN_AVAILABLE and hasattr(self.model, 'predict'):
            # Isolation Forest
            prediction = self.model.predict(X)[0]
            score = self.model.score_samples(X)[0]
            is_anomaly = prediction == -1
        else:
            # Statistical method
            mean = self.model['mean']
            std = self.model['std']

            # Calculate z-score
            z_scores = np.abs((X[0] - mean) / std)
            max_z = np.max(z_scores)

            is_anomaly = max_z > 2.5  # Threshold for anomaly
            score = -max_z

        # Determine reason
        reasons = []
        if current_features['recent_failures'] > 3:
            reasons.append("Multiple failed attempts")
        if current_features['unique_ips'] > 3:
            reasons.append("Multiple IP addresses")
        if current_features['success_rate'] < 0.5:
            reasons.append("Low success rate")
        if current_features['face_detection_rate'] < 0.3:
            reasons.append("Face detection issues")

        reason = "; ".join(reasons) if reasons else "Unusual pattern detected"

        return {
            'is_anomaly': is_anomaly,
            'score': float(score),
            'reason': reason,
            'features': current_features
        }

    def create_alert(self, username, alert_type, description, severity='medium'):
        """Create an anomaly alert."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''
            INSERT INTO anomaly_alerts (username, alert_type, description, severity)
            VALUES (?, ?, ?, ?)
        ''', (username, alert_type, description, severity))

        conn.commit()
        conn.close()

    def get_alerts(self, username=None, unresolved_only=False):
        """Get anomaly alerts."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        query = "SELECT * FROM anomaly_alerts WHERE 1=1"
        params = []

        if username:
            query += " AND username = ?"
            params.append(username)

        if unresolved_only:
            query += " AND resolved = 0"

        query += " ORDER BY alert_time DESC"

        c.execute(query, params)
        alerts = c.fetchall()
        conn.close()

        return alerts

    def analyze_current_login(self, username, ip_address):
        """Full analysis of a login attempt."""
        # Log the attempt
        self.log_login_attempt(username, ip_address, success=True, face_detected=True)

        # Detect anomaly
        result = self.detect_anomaly(username, ip_address)

        if result['is_anomaly']:
            self.create_alert(
                username,
                'ANOMALY_LOGIN',
                result['reason'],
                severity='high' if result['score'] < -0.7 else 'medium'
            )

        return result


# Simple rule-based detector as fallback
class RuleBasedDetector:
    """Simple rule-based anomaly detection when ML is not available."""

    def __init__(self, db_path='users.db'):
        self.db_path = db_path

    def check_login(self, username, ip_address, failed_attempts=0):
        """Check login against simple rules."""
        alerts = []

        # Rule 1: Multiple failed attempts
        if failed_attempts >= 3:
            alerts.append({
                'type': 'MULTIPLE_FAILURES',
                'severity': 'high',
                'message': f'{failed_attempts} failed login attempts detected'
            })

        # Rule 2: Check if IP is new (would need IP history in real implementation)

        # Rule 3: Time-based check (logins at unusual hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 23:
            alerts.append({
                'type': 'UNUSUAL_TIME',
                'severity': 'low',
                'message': f'Login at unusual hour: {current_hour}:00'
            })

        return {
            'is_suspicious': len(alerts) > 0,
            'alerts': alerts
        }
    