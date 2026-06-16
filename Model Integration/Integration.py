import joblib
import re
import sys
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import warnings

# Suppress scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning)

# SQL Injection patterns
SQLI_PATTERNS = [
    r"(?i)(\\')\s*(OR|AND)\s*[\d\w]+(\s*)(=|<|>|LIKE)(\s*)[\d\w']+", # Basic OR/AND injection
    r"(?i)\b((?:select|update|delete|insert|drop|alter|union|exec|execute|into|from|where|group\s+by|order\s+by|having|values)\b.*?\b(?:from|into|values|exec|update|delete|drop|alter)\b)",  # SQL keywords
    r"(?i);\s*(?:drop|create|alter|truncate|select|update|delete)\s+",  # Chained queries
    r"(?i)\bOR\b\s+[\w\d_]+\s*=\s*[\w\d_]+",  # OR-based injections
    r"(?i)--[^\n]*",  # Comment-based injections
    r"(?i)'\s*[\d\w\-_&\*]+\s*(=|LIKE)\s*'[\w\d\-_&\*]+",  # Quote manipulations
    r"(?i)/\*.*\*/",  # Multi-line comments
    r"(?i)\b(sleep|delay|waitfor|pg_sleep)\s*\(\s*\d+\s*\)",  # Time-based injections
    r"(?i)(?:union).*(?:select)"  # UNION-based injections
]

# XSS patterns
XSS_PATTERNS = [
    r"(?i)<[^\w<>]*(?:[^<>\"'\s]*:)?[^\w<>]*(?:\W*s\W*c\W*r\W*i\W*p\W*t|\W*f\W*o\W*r\W*m|\W*s\W*t\W*y\W*l\W*e|\W*o\W*b\W*j\W*e\W*c\W*t|\W*a\W*p\W*p\W*l\W*e\W*t|\W*e\W*m\W*b\W*e\W*d|\W*i\W*m\W*g)",  # Basic script tags
    r"(?i)(?:<script.*?>.*?<\/script>|<.*?\s+on\w+\s*=.*?>)",  # Script tags and event handlers
    r"(?i)(javascript:|vbscript:|data:text\/html)",  # Malicious protocol handlers
    r"(?i)(?:<style.*?>.*?(expression|javascript|behavior).*?<\/style>)",  # Malicious style elements
    r"(?i)(?:<svg.*?>.*?(?:on\w+\s*=.*?).*?<\/svg>)",  # SVG with event handlers
    r"(?i)(?:<script[^>]*>[\s\S]*?<\/script>)",  # Basic script tag
    r"(?i)(?:<[^>]*onmouseover[^>]*>)",  # onmouseover handlers
    r"(?i)(?:<[^>]*onclick[^>]*>)",  # onclick handlers
    r"(?i)(?:<[^>]*onload[^>]*>)",  # onload handlers
    r"(?i)(?:<[^>]*onerror[^>]*>)",  # onerror handlers
    r"(?i)(?:<[^>]*<img[^>]*src[^>]*>)",  # Nested img tags
    r"(?i)(?:<img[^>]*script[^>]*>)",  # img tags with script
    r"(?i)(?:<[^>]*?=.*(alert|confirm|prompt)\s*\(.*\).*>)"  # Direct JavaScript function calls
]

print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")

# Display scikit-learn version
import sklearn
print(f"scikit-learn version: {sklearn.__version__}")

# Load the model
model_path = 'xss_sqli_model.pkl'
print(f"\nLoading model from: {os.path.abspath(model_path)}")
model = joblib.load(model_path)
print("Model loaded successfully!")

# Print model information
print(f"Model type: {type(model).__name__}")
print(f"Number of features: {model.n_features_in_}")
print(f"Classes: {model.classes_}")

# Class for security analysis
class SecurityAnalyzer:
    def __init__(self, model=None):
        self.model = model
        
    def check_sqli(self, text):
        """Check for SQL injection using regex patterns"""
        return any(re.search(pattern, text) for pattern in SQLI_PATTERNS)
    
    def check_xss(self, text):
        """Check for XSS using regex patterns"""
        return any(re.search(pattern, text) for pattern in XSS_PATTERNS)
    
    def analyze(self, text):
        """Analyze text for security threats"""
        # First check using regex patterns
        is_sqli = self.check_sqli(text)
        is_xss = self.check_xss(text)
        
        # Determine result based on regex patterns
        if is_sqli:
            pattern_result = "SQL_INJECTION"
            pattern_prediction = 1
        elif is_xss:
            pattern_result = "XSS"
            pattern_prediction = 2
        else:
            pattern_result = "NORMAL"
            pattern_prediction = 0
            
        # Create response
        response = {
            'input': text,
            'prediction': pattern_prediction,
            'result': pattern_result,
            'detection_method': 'regex_patterns',
            'threat_detected': pattern_prediction != 0
        }
        
        return response

# Create security analyzer
analyzer = SecurityAnalyzer(model)

# Test the analyzer on examples
print("\n--- Testing security analyzer on examples ---")
examples = [
    "Hello world",                              # Normal
    "' OR 1=1 --",                            # SQL injection
    "<script>alert('XSS')</script>",           # XSS
    "admin'; DROP TABLE users; --",            # SQL injection
    "<img src=x onerror=alert(1)>",           # XSS
    "Buy groceries tomorrow",                  # Normal
    "SELECT * FROM users WHERE username = 'admin'",  # SQL injection
    "<a href='javascript:alert(1)'>Click me</a>",    # XSS
]

# Test each example
for text in examples:
    try:
        result = analyzer.analyze(text)
        print(f"Input: {text}")
        print(f"Result: {result['result']} (detected by {result['detection_method']})")
        print(f"Threat detected: {result['threat_detected']}\n")
    except Exception as e:
        print(f"Error analyzing '{text}': {e}\n")
