import joblib
import os
import re
import sys

# SQL Injection regex patterns for fallback detection
SQLI_PATTERNS = [
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION)\b",
    r"['\"]\s*OR\s+.*?=.*?\s*--",
    r"['\"]\s*OR\s+[\d]+=[\d]+.*?--",
    r";\s*DROP\s+TABLE",
    r"--\s*$",
    r"\bOR\s+[\d]+=\d+",
    r"\b\d+\s*=\s*\d+\s*--"
]

# XSS regex patterns for fallback detection
XSS_PATTERNS = [
    r"<[\s]*script[^>]*>[\s\S]*?<[\s]*/[\s]*script[\s]*>",
    r"<[\s]*iframe[^>]*>[\s\S]*?<[\s]*/[\s]*iframe[\s]*>",
    r"javascript:\S+",
    r"<[\s]*img[^>]*onerror[^>]*>",
    r"on(load|error|click|mouseover|focus)\s*=",
    r"<[\s]*body[^>]*onload[^>]*>"
]

def colorize(text, color_code):
    """Add color to terminal output"""
    return f"\033[{color_code}m{text}\033[0m"

def red(text):
    return colorize(text, "91")

def green(text):
    return colorize(text, "92")

def yellow(text):
    return colorize(text, "93")

def blue(text):
    return colorize(text, "94")

def scan_input(input_text, model=None):
    """Scan input text for XSS and SQL Injection attacks"""
    
    # Try ML model if available
    if model is not None:
        try:
            # Make prediction using the model
            prediction = model.predict([input_text])[0]
            
            # Map prediction to result
            result = {
                0: "NORMAL",
                1: "SQL_INJECTION",
                2: "XSS"
            }.get(prediction, "UNKNOWN")
            
            print(f"Using ML model for detection: {blue('ML MODEL')}")
            return {
                'prediction': int(prediction),
                'result': result,
                'threat_detected': prediction != 0,
                'detection_method': 'ml_model'
            }
            
        except Exception as e:
            print(f"Error using ML model: {e}")
            print("Falling back to regex pattern matching...")
    
    # Fallback to regex pattern matching
    # Check for SQL Injection using regex
    is_sqli = any(re.search(pattern, input_text, re.IGNORECASE) for pattern in SQLI_PATTERNS)
    
    # Check for XSS using regex
    is_xss = any(re.search(pattern, input_text, re.IGNORECASE) for pattern in XSS_PATTERNS)
    
    # Determine prediction
    if is_sqli:
        prediction = 1
        result = "SQL_INJECTION"
    elif is_xss:
        prediction = 2
        result = "XSS"
    else:
        prediction = 0
        result = "NORMAL"
    
    print(f"Using pattern matching for detection: {blue('REGEX')}")
    return {
        'prediction': prediction,
        'result': result,
        'threat_detected': prediction != 0,
        'detection_method': 'regex_patterns'
    }

def main():
    print(blue("=" * 60))
    print(blue("       XSS and SQL Injection Security Scanner"))
    print(blue("=" * 60))
    
    # Load the ML model
    model_path = os.path.join(os.path.dirname(__file__), 'xss_sqli_model.pkl')
    print(f"Attempting to load model from: {model_path}")
    model = None
    
    try:
        model = joblib.load(model_path)
        print(green("✓ ML model loaded successfully!"))
    except Exception as e:
        print(red(f"✗ Error loading model: {e}"))
        print(yellow("! Will use regex pattern matching only"))
    
    print(blue("-" * 60))
    print("Test examples: ")
    print("  SQL Injection: ' OR 1=1 --")
    print("  XSS: <script>alert('XSS')</script>")
    print("  Normal: Hello world")
    print(blue("-" * 60))
    
    while True:
        try:
            print("\nEnter text to scan (or 'exit' to quit):")
            input_text = input("> ")
            
            if input_text.lower() in ['exit', 'quit', 'q']:
                break
                
            if not input_text.strip():
                continue
                
            result = scan_input(input_text, model)
            
            if result['threat_detected']:
                if result['result'] == 'SQL_INJECTION':
                    print(red(f"⚠️ SQL INJECTION DETECTED!"))
                elif result['result'] == 'XSS':
                    print(yellow(f"⚠️ XSS ATTACK DETECTED!"))
                print(f"Input: {input_text}")
                print(f"Detection method: {result['detection_method']}")
            else:
                print(green("✓ Input appears to be safe"))
                print(f"Input: {input_text}")
                print(f"Detection method: {result['detection_method']}")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(red(f"Error: {e}"))
    
    print(blue("\nThanks for using the security scanner!"))

if __name__ == "__main__":
    main()
