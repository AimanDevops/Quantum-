"""
AI Student Ranking Module with NLP Sentiment Analysis
Analyzes teacher feedback comments to generate sentiment scores
and combines with grades for fair student ranking.
"""

import sqlite3
import re
from collections import defaultdict

# Simple sentiment lexicon (can be replaced with VADER or TextBlob)
SENTIMENT_WORDS = {
    'positive': [
        'excellent', 'outstanding', 'great', 'good', 'amazing', 'fantastic', 'wonderful',
        'brilliant', 'impressive', 'exceptional', 'superb', 'remarkable', 'perfect',
        'best', 'awesome', 'incredible', 'talented', 'hardworking', 'dedicated',
        'motivated', 'enthusiastic', 'creative', 'innovative', 'intelligent', 'smart',
        'skilled', 'proficient', 'capable', 'promising', 'bright', 'exemplary',
        'commendable', 'satisfactory', 'pleased', 'happy', 'positive', 'helpful',
        'cooperative', 'responsible', 'reliable', 'consistent', 'improving', 'progress'
    ],
    'negative': [
        'poor', 'bad', 'terrible', 'awful', 'worst', 'disappointing', 'unsatisfactory',
        'weak', 'struggling', 'lazy', 'unmotivated', 'careless', 'irresponsible',
        'inconsistent', 'unreliable', 'problematic', 'difficult', 'troubled',
        'concerning', 'worried', 'unsatisfactory', 'below', 'average', 'needs',
        'improvement', 'lacking', 'missing', 'incomplete', 'late', 'absent',
        'distracted', 'unfocused', 'disruptive', 'uncooperative', 'rude'
    ],
    'intensifiers': {
        'very': 1.5, 'extremely': 2.0, 'highly': 1.8, 'really': 1.4,
        'quite': 1.2, 'somewhat': 0.8, 'slightly': 0.6, 'barely': 0.4,
        'absolutely': 2.0, 'totally': 1.8, 'completely': 1.8
    }
}


class SentimentAnalyzer:
    """NLP-based sentiment analyzer for teacher feedback."""

    def __init__(self):
        self.positive_words = set(SENTIMENT_WORDS['positive'])
        self.negative_words = set(SENTIMENT_WORDS['negative'])
        self.intensifiers = SENTIMENT_WORDS['intensifiers']

    def analyze(self, text):
        """
        Analyze sentiment of feedback text.
        Returns sentiment score between -1.0 (very negative) and +1.0 (very positive)
        """
        if not text or not isinstance(text, str):
            return 0.0

        text = text.lower()
        words = re.findall(r'\b\w+\b', text)

        positive_score = 0
        negative_score = 0

        i = 0
        while i < len(words):
            word = words[i]
            multiplier = 1.0

            # Check for intensifier before sentiment word
            if i > 0 and words[i-1] in self.intensifiers:
                multiplier = self.intensifiers[words[i-1]]

            if word in self.positive_words:
                positive_score += multiplier
            elif word in self.negative_words:
                negative_score += multiplier

            i += 1

        # Calculate final sentiment score
        total = positive_score + negative_score
        if total == 0:
            return 0.0

        sentiment = (positive_score - negative_score) / total
        return max(-1.0, min(1.0, sentiment))  # Clamp between -1 and 1

    def get_sentiment_label(self, score):
        """Convert numeric score to label."""
        if score >= 0.5:
            return "Very Positive"
        elif score >= 0.2:
            return "Positive"
        elif score > -0.2:
            return "Neutral"
        elif score > -0.5:
            return "Negative"
        else:
            return "Very Negative"


class StudentRanker:
    """AI-powered student ranking system combining grades and sentiment."""

    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.sentiment_analyzer = SentimentAnalyzer()

    def grade_to_numeric(self, grade):
        """Convert letter grade to numeric score (0-100)."""
        grade_map = {
            'A+': 95, 'A': 90, 'A-': 87,
            'B+': 83, 'B': 80, 'B-': 77,
            'C+': 73, 'C': 70, 'C-': 67,
            'D+': 63, 'D': 60, 'D-': 57,
            'F': 40
        }
        return grade_map.get(grade.upper(), 50)

    def calculate_feedback_sentiment(self, student_username):
        """Calculate average sentiment score from all teacher feedback for a student."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT comment FROM feedback WHERE student = ?", (student_username,))
        comments = c.fetchall()
        conn.close()

        if not comments:
            return 0.0, 0

        total_sentiment = 0
        for (comment,) in comments:
            total_sentiment += self.sentiment_analyzer.analyze(comment)

        avg_sentiment = total_sentiment / len(comments)
        return avg_sentiment, len(comments)

    def get_student_grades(self, student_username):
        """Get all grades for a student."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            SELECT course, assessment, score, grade 
            FROM grades 
            WHERE student_id = ?
        """, (student_username,))
        grades = c.fetchall()
        conn.close()

        return grades

    def calculate_academic_score(self, grades):
        """Calculate weighted academic score from grades."""
        if not grades:
            return 50.0  # Default neutral score

        total_score = 0
        for _, _, score_str, grade in grades:
            # Parse score (e.g., "85/100" -> 85)
            try:
                if '/' in score_str:
                    score = float(score_str.split('/')[0])
                else:
                    score = self.grade_to_numeric(grade)
                total_score += score
            except:
                total_score += self.grade_to_numeric(grade)

        return total_score / len(grades)

    def calculate_ranking_score(self, student_username):
        """
        Calculate comprehensive ranking score combining:
        - Academic performance (60% weight)
        - Teacher feedback sentiment (40% weight)
        """
        # Get academic score
        grades = self.get_student_grades(student_username)
        academic_score = self.calculate_academic_score(grades)

        # Get sentiment score (convert -1 to 1 range to 0 to 100)
        sentiment, feedback_count = self.calculate_feedback_sentiment(student_username)
        sentiment_score = (sentiment + 1) * 50  # Convert to 0-100 scale

        # Weighted combination
        final_score = (academic_score * 0.6) + (sentiment_score * 0.4)

        return {
            'student': student_username,
            'academic_score': round(academic_score, 2),
            'sentiment_score': round(sentiment_score, 2),
            'sentiment_label': self.sentiment_analyzer.get_sentiment_label(sentiment),
            'feedback_count': feedback_count,
            'final_score': round(final_score, 2),
            'grades': grades
        }

    def rank_all_students(self):
        """Rank all students and return sorted list."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Get all unique students with grades or feedback
        c.execute("""
            SELECT DISTINCT student_id FROM grades
            UNION
            SELECT DISTINCT student FROM feedback
        """)
        students = [row[0] for row in c.fetchall()]
        conn.close()

        rankings = []
        for student in students:
            ranking_data = self.calculate_ranking_score(student)
            rankings.append(ranking_data)

        # Sort by final score (descending)
        rankings.sort(key=lambda x: x['final_score'], reverse=True)

        # Add rank position
        for i, rank in enumerate(rankings, 1):
            rank['rank'] = i

        return rankings

    def save_rankings_to_db(self):
        """Save rankings to database for persistence."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Create rankings table if not exists
        c.execute('''
            CREATE TABLE IF NOT EXISTS student_rankings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student TEXT UNIQUE,
                academic_score REAL,
                sentiment_score REAL,
                final_score REAL,
                rank_position INTEGER,
                sentiment_label TEXT,
                feedback_count INTEGER,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        rankings = self.rank_all_students()

        for rank in rankings:
            c.execute('''
                INSERT OR REPLACE INTO student_rankings 
                (student, academic_score, sentiment_score, final_score, rank_position, sentiment_label, feedback_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                rank['student'],
                rank['academic_score'],
                rank['sentiment_score'],
                rank['final_score'],
                rank['rank'],
                rank['sentiment_label'],
                rank['feedback_count']
            ))

        conn.commit()
        conn.close()
        return rankings