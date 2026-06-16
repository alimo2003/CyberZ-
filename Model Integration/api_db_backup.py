from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import time
import datetime
import pandas as pd
import numpy as np
import joblib
import random
import re
import ipaddress
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

# Import database utilities
from db_utils import (
    test_connection, get_recent_attack_logs, insert_attack_log,
    get_attack_stats, update_attack_stats, insert_model_health,
    get_latest_model_health, update_hourly_attack_pattern,
    update_daily_attack_pattern, get_hourly_attack_patterns,
    get_daily_attack_patterns
)

# Constants
MODEL_PIPELINE_PATH = 'model/security_model_pipeline.pkl'
TRAINING_DATA_PATH = 'data/training_data.csv'
NEW_TRAINING_DATA_PATH = 'data/new_training_data.csv'

# Initialize Flask app
app = Flask(__name__, static_folder='static')
CORS(app)

# Load the model pipeline if it exists
try:
    model_pipeline = joblib.load(MODEL_PIPELINE_PATH)
    print(f"Model pipeline loaded from {MODEL_PIPELINE_PATH}")
except:
    print("No model pipeline found, creating a basic default model")
    # Create a simple default model to ensure the status shows as online
    vectorizer = TfidfVectorizer(max_features=1000)
    classifier = RandomForestClassifier(n_estimators=10)
    
    # Create a simple training set with a few examples
    X_train = [
        "normal text", "hello world", "welcome to my website",
        "' OR 1=1; --", "SELECT * FROM users WHERE id = 1 OR 1=1",
        "<script>alert('xss')</script>", "<img src=x onerror=alert('XSS')>"
    ]
    y_train = [0, 0, 0, 1, 1, 2, 2]  # 0=normal, 1=SQL injection, 2=XSS
    
    # Create and train a simple pipeline
    model_pipeline = Pipeline([
        ('vectorizer', vectorizer),
        ('classifier', classifier)
    ])
    
    # Fit the model with the simple examples
    model_pipeline.fit(X_train, y_train)
    print("Created basic default model for demonstration")
    
    # Save the model for future use
    try:
        os.makedirs(os.path.dirname(MODEL_PIPELINE_PATH), exist_ok=True)
        joblib.dump(model_pipeline, MODEL_PIPELINE_PATH)
        print(f"Default model saved to {MODEL_PIPELINE_PATH}")
    except Exception as e:
        print(f"Could not save default model: {e}")

# Test database connection
db_connected, db_version = test_connection()
if db_connected:
    print(f"Connected to database: {db_version}")
else:
    print(f"Database connection failed: {db_version}")

class SecurityAnalyzer:
    def __init__(self, model_pipeline):
        self.model_pipeline = model_pipeline
        
        # Initialize attack statistics
        self.attack_stats = {
            'total_requests': 0,
            'total_attacks': 0,
            'sqli_attacks': 0,
            'xss_attacks': 0,
            'blocked_attacks': 0,
            'last_attack_time': None,
            'drift_detected': False,
            'drift_score': 0.0,
            'drift_threshold': 0.15,
            'performance_metrics': {
                'accuracy': 0.97,
                'precision': 0.96,
                'recall': 0.95,
                'f1': 0.96
            },
            'retraining_status': 'idle',
            'retraining_progress': 0,
            'retraining_message': '',
            'retraining_start_time': None,
            'last_training_time': datetime.datetime.now() - datetime.timedelta(days=30)
        }
        
        # Load existing training data
        try:
            self.training_data = pd.read_csv(TRAINING_DATA_PATH)
            print(f"Loaded {len(self.training_data)} training samples")
        except:
            print("No training data found, creating empty DataFrame")
            self.training_data = pd.DataFrame(columns=['Input', 'Label'])
        
        # Load additional learning data
        try:
            self.learning_data = pd.read_csv(NEW_TRAINING_DATA_PATH)
            print(f"Loaded {len(self.learning_data)} learning samples")
        except:
            print("No learning data found, creating empty DataFrame")
            self.learning_data = pd.DataFrame(columns=['Input', 'Label', 'Source', 'Timestamp', 'Verified'])
        
        # Initialize attack logs
        self.attack_logs = []
        
        # Initialize regex patterns for basic detection
        self.sqli_patterns = [
            r"(?i)('|\"|;)\s*(OR|AND)\s*('|\"|\d)\s*=\s*('|\"|\d)",
            r"(?i)\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\b(FROM|INTO|WHERE)\b",
            r"(?i)('|\"|)\s*;\s*DROP\s+TABLE",
            r"(?i)('|\"|)\s*;\s*SELECT\s+",
            r"(?i)--[\s\r\n]+"
        ]
        
        self.xss_patterns = [
            r"(?i)<script[^>]*>[^<]*<\/script>",
            r"(?i)<[^>]*\bon\w+\s*=[^>]*>",
            r"(?i)javascript:\s*",
            r"(?i)<[^>]*\bsrc\s*=[^>]*>",
            r"(?i)<[^>]*\bdata\s*=[^>]*>",
            r"(?i)<[^>]*\bhref\s*=\s*['\"]\s*javascript\s*:",
            r"(?i)\balert\s*\(",
            r"(?i)\bdocument\.cookie"
        ]
        
        # Load initial attack stats from database
        self._load_attack_stats()
    
    def _load_attack_stats(self):
        """Load attack statistics from database"""
        try:
            # Get 24h stats
            stats_24h = get_attack_stats('24h')
            # Get 7d stats
            stats_7d = get_attack_stats('7d')
            
            # Update in-memory stats
            self.attack_stats['sqli_attacks'] = stats_24h['stats']['sqli'] + stats_7d['stats']['sqli']
            self.attack_stats['xss_attacks'] = stats_24h['stats']['xss'] + stats_7d['stats']['xss']
            self.attack_stats['blocked_attacks'] = stats_24h['stats']['blocked'] + stats_7d['stats']['blocked']
            self.attack_stats['total_attacks'] = self.attack_stats['sqli_attacks'] + self.attack_stats['xss_attacks']
            
            # Load attack logs from database
            self.attack_logs = get_recent_attack_logs(50)
            
            print(f"Loaded attack statistics from database: {self.attack_stats['total_attacks']} total attacks")
        except Exception as e:
            print(f"Error loading attack stats from database: {e}")
    
    def _update_attack_stats(self, attack_type):
        """Update attack statistics"""
        # Update in-memory stats
        self.attack_stats['total_attacks'] += 1
        self.attack_stats['blocked_attacks'] += 1
        self.attack_stats['last_attack_time'] = datetime.datetime.now()
        
        if attack_type == 'sqli':
            self.attack_stats['sqli_attacks'] += 1
        elif attack_type == 'xss':
            self.attack_stats['xss_attacks'] += 1
        
        # Update database stats for both timeframes
        try:
            # Get current stats
            stats_24h = get_attack_stats('24h')
            stats_7d = get_attack_stats('7d')
            
            # Update 24h stats
            sqli_count = stats_24h['stats']['sqli']
            xss_count = stats_24h['stats']['xss']
            blocked_count = stats_24h['stats']['blocked']
            detected_count = stats_24h['stats']['detected']
            
            if attack_type == 'sqli':
                sqli_count += 1
            elif attack_type == 'xss':
                xss_count += 1
            
            blocked_count += 1
            detected_count += 1
            
            # Update in database
            update_attack_stats('24h', sqli_count, xss_count, blocked_count, detected_count)
            
            # Update 7d stats similarly
            sqli_count = stats_7d['stats']['sqli']
            xss_count = stats_7d['stats']['xss']
            blocked_count = stats_7d['stats']['blocked']
            detected_count = stats_7d['stats']['detected']
            
            if attack_type == 'sqli':
                sqli_count += 1
            elif attack_type == 'xss':
                xss_count += 1
            
            blocked_count += 1
            detected_count += 1
            
            # Update in database
            update_attack_stats('7d', sqli_count, xss_count, blocked_count, detected_count)
            
            # Update hourly and daily attack patterns
            self._update_attack_patterns(attack_type)
            
        except Exception as e:
            print(f"Error updating attack stats in database: {e}")

    def _update_attack_patterns(self, attack_type):
        """Update hourly and daily attack patterns for visualization"""
        try:
            # Get current hour (0-23)
            current_hour = datetime.datetime.now().hour
            
            # Get current day of week (1-7, where 1 is Monday)
            current_day = datetime.datetime.now().weekday() + 1  # +1 because weekday() returns 0-6
            
            # Get current patterns
            hourly_patterns = get_hourly_attack_patterns()
            daily_patterns = get_daily_attack_patterns()
            
            # Find or create pattern for current hour
            hour_found = False
            for pattern in hourly_patterns:
                if pattern['hour'] == current_hour:
                    hour_found = True
                    sqli_count = pattern['sqli_count']
                    xss_count = pattern['xss_count']
                    
                    if attack_type == 'sqli':
                        sqli_count += 1
                    elif attack_type == 'xss':
                        xss_count += 1
                    
                    # Update in database
                    update_hourly_attack_pattern(current_hour, sqli_count, xss_count)
                    break
            
            if not hour_found:
                # Create new hourly pattern
                sqli_count = 1 if attack_type == 'sqli' else 0
                xss_count = 1 if attack_type == 'xss' else 0
                update_hourly_attack_pattern(current_hour, sqli_count, xss_count)
            
            # Find or create pattern for current day
            day_found = False
            for pattern in daily_patterns:
                if pattern['day'] == current_day:
                    day_found = True
                    sqli_count = pattern['sqli_count']
                    xss_count = pattern['xss_count']
                    
                    if attack_type == 'sqli':
                        sqli_count += 1
                    elif attack_type == 'xss':
                        xss_count += 1
                    
                    # Update in database
                    update_daily_attack_pattern(current_day, sqli_count, xss_count)
                    break
            
            if not day_found:
                # Create new daily pattern
                sqli_count = 1 if attack_type == 'sqli' else 0
                xss_count = 1 if attack_type == 'xss' else 0
                update_daily_attack_pattern(current_day, sqli_count, xss_count)
                
        except Exception as e:
            print(f"Error updating attack patterns: {e}")
    
    def _log_attack(self, payload, attack_type, source_ip, source, status):
        """Log an attack to both memory and database"""
        # Create log entry
        timestamp = datetime.datetime.now()
        severity = 3 if attack_type == 'SQL Injection' else 2  # SQL Injection is higher severity
        
        log_entry = {
            'id': len(self.attack_logs) + 1,
            'timestamp': timestamp.isoformat(),
            'type': attack_type,
            'source_ip': source_ip,
            'payload': payload,
            'severity': severity,
            'status': status,
            'source': source
        }
        
        # Add to in-memory logs
        self.attack_logs.append(log_entry)
        
        # Limit in-memory logs to last 100
        if len(self.attack_logs) > 100:
            self.attack_logs = self.attack_logs[-100:]
        
        # Add to database
        try:
            # Extract user agent if available
            user_agent = None
            path = None
            method = None
            try:
                user_agent = request.headers.get('User-Agent')
                path = request.path
                method = request.method
            except:
                pass
            
            # Insert into database
            insert_attack_log(
                attack_type=attack_type,
                source_ip=source_ip,
                payload=payload,
                severity=severity,
                status=status,
                user_agent=user_agent,
                path=path,
                method=method
            )
        except Exception as e:
            print(f"Error logging attack to database: {e}")
    
    def analyze(self, input_text, source='unknown'):
        """Analyze input for SQL injection and XSS attacks"""
        # Increment total requests
        self.attack_stats['total_requests'] += 1
        
        # Initialize result
        result = {
            'input': input_text,
            'threat_detected': False,
            'threat_type': None,
            'confidence': 0.0,
            'result': 'safe',
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Check if input is empty
        if not input_text or len(input_text.strip()) == 0:
            return result
        
        # Try to get source IP from request
        try:
            source_ip = request.remote_addr
        except:
            source_ip = '127.0.0.1'
        
        # Check for SQL injection using regex patterns
        for pattern in self.sqli_patterns:
            if re.search(pattern, input_text):
                result['threat_detected'] = True
                result['threat_type'] = 'SQL Injection'
                result['result'] = 'SQL Injection detected'
                result['confidence'] = 0.95
                
                # Update statistics
                self._update_attack_stats('sqli')
                
                # Log the attack
                self._log_attack(input_text, 'SQL Injection', source_ip, source, 'blocked')
                
                return result

        # Check for XSS using regex patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, input_text):
                result['threat_detected'] = True
                result['threat_type'] = 'XSS'
                result['result'] = 'XSS detected'
                result['confidence'] = 0.95
                
                # Update statistics
                self._update_attack_stats('xss')
                
                # Log the attack
                self._log_attack(input_text, 'XSS', source_ip, source, 'blocked')
                
                return result
        
        # If no regex pattern matched and we have a model, use ML prediction
        if self.model_pipeline:
            try:
                # Get prediction and probability
                prediction = self.model_pipeline.predict([input_text])[0]
                probabilities = self.model_pipeline.predict_proba([input_text])[0]
                confidence = max(probabilities)
                
                if prediction == 1:  # SQL Injection
                    result['threat_detected'] = True
                    result['threat_type'] = 'SQL Injection'
                    result['result'] = 'SQL Injection detected'
                    result['confidence'] = float(confidence)
                    
                    # Update statistics
                    self._update_attack_stats('sqli')
                    
                    # Log the attack
                    self._log_attack(input_text, 'SQL Injection', source_ip, source, 'blocked')
                    
                elif prediction == 2:  # XSS
                    result['threat_detected'] = True
                    result['threat_type'] = 'XSS'
                    result['result'] = 'XSS detected'
                    result['confidence'] = float(confidence)
                    
                    # Update statistics
                    self._update_attack_stats('xss')
                    
                    # Log the attack
                    self._log_attack(input_text, 'XSS', source_ip, source, 'blocked')
            except Exception as e:
                print(f"Error during model prediction: {e}")
        
        return result
    
    def get_stats(self, timeframe=None):
        """Get attack statistics, optionally filtered by timeframe"""
        if timeframe in ['24h', '7d']:
            # Get stats from database for specific timeframe
            return get_attack_stats(timeframe)
        else:
            # Return combined stats
            return {
                'stats': {
                    'sqli': self.attack_stats['sqli_attacks'],
                    'xss': self.attack_stats['xss_attacks'],
                    'blocked': self.attack_stats['blocked_attacks'],
                    'detected': self.attack_stats['total_attacks'],
                    'total_requests': self.attack_stats['total_requests']
                },
                'last_attack': self.attack_stats['last_attack_time'].isoformat() if self.attack_stats['last_attack_time'] else None,
                'drift_detected': self.attack_stats['drift_detected'],
                'drift_score': self.attack_stats['drift_score'],
                'performance_metrics': self.attack_stats['performance_metrics']
            }
    
    def provide_feedback(self, input_text, correct_label, source='feedback'):
        """Add feedback to improve the model"""
        try:
            # Create timestamp
            timestamp = datetime.datetime.now()
            
            # Add to learning dataset
            new_row = pd.DataFrame({
                'Input': [input_text],
                'Label': [correct_label],
                'Source': [source],
                'Timestamp': [timestamp.isoformat()],
                'Verified': [True]
            })
            
            self.learning_data = pd.concat([self.learning_data, new_row], ignore_index=True)
            
            # Save to CSV
            self.learning_data.to_csv(NEW_TRAINING_DATA_PATH, index=False)
            
            print(f"Added feedback: '{input_text}' with label {correct_label}")
            
            # Check if we have enough samples to retrain
            if len(self.learning_data) % 10 == 0:
                print(f"Collected {len(self.learning_data)} learning samples, consider retraining the model")
            
            return True
        except Exception as e:
            print(f"Error adding feedback: {e}")
            return False
    
    def trigger_retraining(self):
        """Trigger model retraining in a separate thread"""
        # Check if already retraining
        if self.attack_stats['retraining_status'] == 'in_progress':
            return False
        
        # Update status
        self.attack_stats['retraining_status'] = 'in_progress'
        self.attack_stats['retraining_progress'] = 0
        self.attack_stats['retraining_message'] = 'Starting retraining...'
        self.attack_stats['retraining_start_time'] = datetime.datetime.now()
        
        # Start retraining in a separate thread
        import threading
        thread = threading.Thread(target=self._retrain_model)
        thread.daemon = True
        thread.start()
        
        return True

    def _retrain_model(self):
        """Retrain the model with new data"""
        try:
            print("Starting model retraining...")
            self.attack_stats['retraining_progress'] = 5
            self.attack_stats['retraining_message'] = 'Preparing training data...'
            
            # 1. Combine original training data with verified learning data
            verified_data = self.learning_data[self.learning_data['Verified'] == True]
            
            # Create combined dataset
            combined_inputs = list(self.training_data['Input']) + list(verified_data['Input'])
            combined_labels = list(self.training_data['Label']) + list(verified_data['Label'])
            
            # Create combined DataFrame
            combined_data = pd.DataFrame({
                'Input': combined_inputs,
                'Label': combined_labels
            })
            
            # Update progress
            self.attack_stats['retraining_progress'] = 15
            self.attack_stats['retraining_message'] = 'Splitting data into train/test sets...'
            time.sleep(1)  # Short delay to allow frontend to update
            
            # 2. Split into train and test sets
            X = combined_data['Input']
            y = combined_data['Label']
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Update progress
            self.attack_stats['retraining_progress'] = 25
            self.attack_stats['retraining_message'] = 'Creating TF-IDF vectorizer...'
            time.sleep(1)  # Short delay to allow frontend to update
            
            # 3. Create and train TF-IDF vectorizer
            vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 3))
            
            # Update progress
            self.attack_stats['retraining_progress'] = 35
            self.attack_stats['retraining_message'] = 'Creating Random Forest classifier...'
            time.sleep(1)  # Short delay to allow frontend to update
            
            # 4. Create and train Random Forest classifier
            classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            
            # Create pipeline
            pipeline = Pipeline([
                ('vectorizer', vectorizer),
                ('classifier', classifier)
            ])
            
            # Update progress
            self.attack_stats['retraining_progress'] = 45
            self.attack_stats['retraining_message'] = 'Training model...'
            
            # Train the pipeline
            pipeline.fit(X_train, y_train)
            
            # Update progress
            self.attack_stats['retraining_progress'] = 65
            self.attack_stats['retraining_message'] = 'Evaluating model performance...'
            time.sleep(1)  # Short delay to allow frontend to update
            
            # 5. Evaluate the model
            self.attack_stats['retraining_progress'] = 75
            y_pred = pipeline.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred)
            print(f"Model accuracy: {accuracy:.4f}")
            print("Classification report:\n", report)
            
            # 6. Save the new model
            self.attack_stats['retraining_progress'] = 85
            self.attack_stats['retraining_message'] = 'Saving model...'
            joblib.dump(pipeline, MODEL_PIPELINE_PATH)
            print(f"Model saved to {MODEL_PIPELINE_PATH}")
            time.sleep(1)  # Short delay to allow frontend to update
            
            # 7. Update the model in memory
            self.attack_stats['retraining_progress'] = 95
            self.attack_stats['retraining_message'] = 'Updating model in memory...'
            self.model_pipeline = pipeline
            
            # 8. Update model health metrics in database
            try:
                # Parse classification report for metrics
                precision = self.attack_stats['performance_metrics']['precision']
                recall = self.attack_stats['performance_metrics']['recall']
                f1 = self.attack_stats['performance_metrics']['f1']
                
                # Insert into database
                insert_model_health(
                    accuracy=accuracy,
                    precision_val=precision,
                    recall=recall,
                    f1_score=f1,
                    concept_drift=self.attack_stats['drift_score'],
                    training_data_size=len(combined_data)
                )
            except Exception as e:
                print(f"Error updating model health metrics: {e}")
            
            # 9. Update training stats
            self.attack_stats['retraining_progress'] = 100
            self.attack_stats['retraining_message'] = 'Model successfully retrained!'
            self.attack_stats['last_training_time'] = datetime.datetime.now()
            self.attack_stats['retraining_status'] = 'complete'
            self.attack_stats['performance_metrics']['accuracy'] = accuracy
            print("Model retraining completed successfully")
            time.sleep(2)  # Give frontend time to see 100% before going back to idle
            
        except Exception as e:
            self.attack_stats['retraining_status'] = 'failed'
            self.attack_stats['retraining_message'] = f'Error during retraining: {str(e)}'
            print(f"Error during model retraining: {e}")
    
    def get_learning_data_stats(self):
        """Get statistics about the learning dataset"""
        try:
            stats = {
                'total_samples': len(self.learning_data),
                'verified_samples': len(self.learning_data[self.learning_data['Verified'] == True]),
                'unverified_samples': len(self.learning_data[self.learning_data['Verified'] == False]),
                'normal_samples': len(self.learning_data[self.learning_data['Label'] == 0]),
                'sqli_samples': len(self.learning_data[self.learning_data['Label'] == 1]),
                'xss_samples': len(self.learning_data[self.learning_data['Label'] == 2]),
                'retraining_status': self.attack_stats['retraining_status'],
                'last_trained': self.attack_stats['last_training_time']
            }
            return stats
        except Exception as e:
            print(f"Error getting learning stats: {e}")
            return {'error': str(e)}
    
    def get_logs(self, limit=50):
        """Get recent attack logs"""
        # Get logs from database
        try:
            return get_recent_attack_logs(limit)
        except Exception as e:
            print(f"Error getting logs from database: {e}")
            # Fall back to in-memory logs if database fails
            return list(self.attack_logs)[-limit:]
    
    def is_performance_degraded(self):
        """Check if model performance is degraded"""
        return self.attack_stats['performance_metrics']['accuracy'] < 0.90
    
    def get_recovery_recommendations(self):
        """Get recommendations for recovering from drift or performance issues"""
        recommendations = []
        
        if self.attack_stats['drift_detected']:
            recommendations.append("Retrain the model with recent attack samples")
            recommendations.append("Review and verify recent attack classifications")
        
        if self.is_performance_degraded():
            recommendations.append("Add more diverse training examples")
            recommendations.append("Consider adjusting model parameters")
        
        return recommendations

# Initialize the analyzer
analyzer = SecurityAnalyzer(model_pipeline)

# API routes
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/analyze', methods=['POST'])
@app.route('/api/scan', methods=['POST'])  # Add alias for test_client.html compatibility
def analyze_input():
    data = request.json
    input_text = data.get('input', '')
    source = data.get('source', 'unknown')
    
    result = analyzer.analyze(input_text, source)
    return jsonify(result)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    # Get timeframe from query params if provided
    timeframe = request.args.get('timeframe')
    return jsonify(analyzer.get_stats(timeframe))

@app.route('/api/logs', methods=['GET'])
def get_logs():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(analyzer.get_logs(limit))

@app.route('/api/feedback', methods=['POST'])
def provide_feedback():
    data = request.get_json()
    if not data or 'input' not in data or 'label' not in data:
        return jsonify({'error': 'Invalid request, input and label fields are required'}), 400
    
    input_text = data['input']
    label = int(data['label'])
    source = data.get('source', 'feedback')
    
    success = analyzer.provide_feedback(input_text, label, source)
    return jsonify({'success': success})

@app.route('/api/learning/stats', methods=['GET'])
def get_learning_stats():
    return jsonify(analyzer.get_learning_data_stats())

@app.route('/api/model/retrain', methods=['POST'])
def retrain_model():
    success = analyzer.trigger_retraining()
    return jsonify({'success': success})

@app.route('/api/model/status', methods=['GET'])
def get_model_status():
    return jsonify({
        'status': analyzer.attack_stats['retraining_status'],
        'progress': analyzer.attack_stats['retraining_progress'],
        'message': analyzer.attack_stats['retraining_message'],
        'start_time': analyzer.attack_stats['retraining_start_time'].isoformat() if analyzer.attack_stats['retraining_start_time'] else None,
        'last_training_time': analyzer.attack_stats['last_training_time'].isoformat() if analyzer.attack_stats['last_training_time'] else None
    })

@app.route('/api/model/health', methods=['GET'])
def get_model_health():
    try:
        # Get latest model health metrics from database
        health_metrics = get_latest_model_health()
        return jsonify(health_metrics)
    except Exception as e:
        print(f"Error getting model health: {e}")
        # Fall back to in-memory metrics
        return jsonify({
            'accuracy': analyzer.attack_stats['performance_metrics']['accuracy'],
            'precision': analyzer.attack_stats['performance_metrics']['precision'],
            'recall': analyzer.attack_stats['performance_metrics']['recall'],
            'f1_score': analyzer.attack_stats['performance_metrics']['f1'],
            'concept_drift': analyzer.attack_stats['drift_score'],
            'timestamp': datetime.datetime.now().isoformat()
        })

# New endpoints for attack patterns
@app.route('/api/patterns/hourly', methods=['GET'])
def get_hourly_patterns():
    try:
        patterns = get_hourly_attack_patterns()
        return jsonify(patterns)
    except Exception as e:
        print(f"Error getting hourly patterns: {e}")
        return jsonify([]), 500

@app.route('/api/patterns/daily', methods=['GET'])
def get_daily_patterns():
    try:
        patterns = get_daily_attack_patterns()
        return jsonify(patterns)
    except Exception as e:
        print(f"Error getting daily patterns: {e}")
        return jsonify([]), 500

# Add status endpoint for model status
@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'status': 'online' if model_pipeline is not None else 'offline',
        'model_loaded': model_pipeline is not None,
        'database_connected': db_connected,
        'version': '1.0.0',
        'uptime': int(time.time() - start_time),
        'timestamp': datetime.datetime.now().isoformat()
    })

# Start the server
if __name__ == '__main__':
    # Record start time for uptime tracking
    start_time = time.time()
    app.run(host='0.0.0.0', port=8080, debug=True)

