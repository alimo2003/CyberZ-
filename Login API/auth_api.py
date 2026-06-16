import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import pyodbc
import hashlib
import jwt
import random
import string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.info("Starting API server")

app = Flask(__name__)
# Enable CORS for all routes with specific configuration
CORS(app, 
    resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "supports_credentials": True,
            "allow_headers": ["Content-Type", "Authorization"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "expose_headers": ["Content-Type", "Content-Length", "Authorization"],
            "max_age": 600  # Cache preflight requests for 10 minutes
        }
    },
    supports_credentials=True
)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'cyberz1234321@gmail.com'
app.config['MAIL_PASSWORD'] = 'dxif hros clzh abhd'  # App Password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Store MFA codes in memory (in production, use Redis or database)
mfa_codes = {}

def get_db_connection():
    conn_str = (
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=localhost\\SQLEXPRESS;'  # Using localhost with SQLEXPRESS instance
        'DATABASE=CyberZ;'
        'Trusted_Connection=yes;'  # Using Windows Authentication
    )
    try:
        conn = pyodbc.connect(conn_str)
        print("Database connection successful")
        return conn
    except pyodbc.Error as e:
        print(f"Database connection error: {e}")
        logger.error(f"Database connection error: {e}")
        raise

def verify_password(stored_password, provided_password, salt):
    logger.info(f"Verifying password - Stored hash: {stored_password}")
    logger.info(f"Salt being used: {salt}")
    logger.info(f"Provided password: {provided_password}")
    
    # Create the input string exactly as stored in the database
    hash_input = (provided_password + salt).encode('utf-8')
    logger.info(f"Hashing input: {hash_input}")
    
    # Generate SHA-256 hash and convert to uppercase to match database format
    test_hash = hashlib.sha256(hash_input).hexdigest().upper()
    logger.info(f"Generated hash: {test_hash}, Length: {len(test_hash)}")
    
    # Compare the hashes
    if test_hash == stored_password:
        logger.info("Password verification succeeded")
        return True
    
    logger.info("Password verification failed - hashes do not match")
    logger.info(f"Expected: {stored_password}")
    logger.info(f"Got:      {test_hash}")
    return False

def generate_token(user_id, username, role_id):
    payload = {
        'user_id': user_id,
        'username': username,
        'role_id': role_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1] if ' ' in request.headers['Authorization'] else None
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = data
        except:
            return jsonify({'message': 'Token is invalid'}), 401
            
        return f(*args, **kwargs)
    return decorated

def generate_mfa_code():
    return ''.join(random.choices(string.digits, k=6))

def store_mfa_code(user_id, code):
    expiry = datetime.utcnow() + timedelta(minutes=5)
    mfa_codes[user_id] = {
        'code': code,
        'expiry': expiry,
        'used': False
    }
    return expiry

def verify_mfa_code(user_id, code):
    if user_id not in mfa_codes:
        return False
    
    mfa_data = mfa_codes[user_id]
    now = datetime.utcnow()
    
    if mfa_data['used'] or mfa_data['expiry'] < now:
        return False
    
    if mfa_data['code'] == code:
        mfa_data['used'] = True
        return True
    
    return False

def send_email(recipient, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = recipient
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/api/login', methods=['POST'])
def login():
    try:
        logger.info("Login attempt received")
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            logger.warning("Invalid login request: missing username or password")
            return jsonify({'message': 'Username and password are required'}), 400
            
        logger.info(f"Attempting to connect to database")
        conn = get_db_connection()
        cursor = conn.cursor()
        
        logger.info(f"Querying user for username: {data['username']}")
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.password_hash, u.salt, 
                   u.role_id, u.is_active, u.is_verified
            FROM Users u
            WHERE u.username = ?
        """, (data['username'],))
        
        user = cursor.fetchone()
        if not user:
            logger.warning(f"User not found: {data['username']}")
            return jsonify({'message': 'User not found'}), 401
            
        logger.info("User found, verifying password")
        logger.info(f"User data from DB - Username: {user[1]}, Role: {user[5]}")
        logger.info(f"Stored hash: {user[3]}, Salt: {user[4]}")
        
        if not verify_password(user[3], data['password'], user[4]):
            logger.warning(f"Invalid password for user: {data['username']}")
            # Update failed login attempt
            cursor.execute("""
                UPDATE Users 
                SET failed_login_attempts = failed_login_attempts + 1,
                    last_failed_login = ?
                WHERE id = ?
            """, (datetime.utcnow(), user[0]))
            conn.commit()
            return jsonify({'message': 'Invalid credentials'}), 401
            
        logger.info(f"Password verification succeeded for user: {data['username']}")
        
        # Reset failed login attempts on successful login
        logger.info("Resetting failed login attempts")
        cursor.execute("""
            UPDATE Users 
            SET failed_login_attempts = 0,
                last_login = ?
            WHERE id = ?
        """, (datetime.utcnow(), user[0]))
        conn.commit()
        
        logger.info("Generating MFA code")
        # Generate MFA code and store in database
        mfa_code = generate_mfa_code()
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        
        # Store in database
        cursor.execute("""
            INSERT INTO MFA_Codes (user_id, code, expires_at, is_used)
            VALUES (?, ?, ?, 0)
        """, (user[0], mfa_code, expires_at))
        conn.commit()
        
        logger.info(f"Sending MFA code to email: {user[2]}")
        # Send MFA code to email
        if not send_email(user[2], "MFA Code", f"Your MFA code is: {mfa_code}"):
            logger.error("Failed to send MFA code")
            return jsonify({'message': 'Failed to send MFA code'}), 500
            
        logger.info("MFA code sent, returning MFA required response")
        
        # Return MFA required response
        return jsonify({
            'message': 'MFA code sent',
            'requires_mfa': True,
            'user_id': user[0],
            'email': user[2],  # user[2] is the email in the SELECT query
            'username': user[1]  # user[1] is the username
        })
        
    except pyodbc.Error as e:
        logger.error(f"Database error: {e}")
        return jsonify({'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'message': 'Internal server error'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
            logger.info("Database connection closed")

@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa():
    try:
        data = request.get_json()
        if not data or 'user_id' not in data or 'code' not in data:
            return jsonify({
                'success': False,
                'message': 'User ID and MFA code are required'
            }), 400
            
        if not verify_mfa_code(data['user_id'], data['code']):
            return jsonify({
                'success': False,
                'message': 'Invalid MFA code'
            }), 401
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user details with role information
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.role_id, u.first_name, u.last_name,
                   COALESCE(r.name, 'user') as role_name
            FROM Users u
            LEFT JOIN Roles r ON u.role_id = r.id
            WHERE u.id = ?
        """, (data['user_id'],))
        
        user = cursor.fetchone()
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404
            
        # Generate JWT token
        token = generate_token(user.id, user.username, user.role_id)
        
        # Update last login
        cursor.execute("""
            UPDATE Users 
            SET last_login = ?
            WHERE id = ?
        """, (datetime.utcnow(), user.id))
        conn.commit()
        
        # Clear MFA code
        if data['user_id'] in mfa_codes:
            del mfa_codes[data['user_id']]
        
        # Determine role name
        role_name = user.role_name.lower() if user.role_name else 'user'
        
        # Prepare user data for response
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'name': full_name or user.username,  # Fallback to username if name is not available
            'role': role_name,
            'role_id': user.role_id
        }
        
        # Create response
        response_data = {
            'success': True,
            'message': 'MFA verification successful',
            'token': token,
            'user': user_data
        }
        
        # Set response headers
        response = jsonify(response_data)
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        
        # Set HTTP-only cookie
        response.set_cookie(
            'auth_token',
            value=token,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite='Lax',
            max_age=86400,  # 24 hours
            path='/'  # Ensure cookie is available on all paths
        )
        
        logger.info(f"MFA verification successful for user: {user.username} (ID: {user.id})")
        return response
        
    except Exception as e:
        print(f"MFA verification error: {e}")
        return jsonify({'message': 'Internal server error'}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        # Clear the auth cookie by setting an expired cookie
        response = jsonify({'message': 'Successfully logged out'})
        response.set_cookie(
            'auth_token',
            value='',
            expires=0,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite='Lax'
        )
        return response, 200
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'message': 'Error during logout'}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify the OTP code for MFA"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        email = data.get('email')
        code = data.get('code')
        
        if not all([user_id, email, code]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
        # Verify the OTP code
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if the OTP is valid
        cursor.execute(
            'SELECT user_id, expires_at FROM MFA_Codes WHERE user_id = ? AND code = ? AND is_used = 0',
            (user_id, code)
        )
        mfa_record = cursor.fetchone()
        
        if not mfa_record:
            return jsonify({
                'success': False,
                'error': 'Invalid or expired verification code'
            }), 400
            
        # Check if the code has expired
        expires_at = mfa_record[1]  # Already a datetime object from SQL Server
        if not isinstance(expires_at, datetime):
            # If for some reason it's a string, parse it
            try:
                expires_at = datetime.strptime(str(expires_at), '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError) as e:
                logger.error(f'Error parsing expires_at: {e}')
                return jsonify({
                    'success': False,
                    'error': 'Invalid expiration time format'
                }), 500
                
        if datetime.utcnow() > expires_at:
            return jsonify({
                'success': False,
                'error': 'Verification code has expired'
            }), 400
        
        # Mark the code as used
        cursor.execute(
            'UPDATE MFA_Codes SET is_used = 1 WHERE user_id = ? AND code = ?',
            (user_id, code)
        )
        
        # Get user data with role information
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.role_id, r.name as role_name
            FROM Users u
            LEFT JOIN Roles r ON u.role_id = r.id
            WHERE u.id = ?
        """, (user_id,))
        user = cursor.fetchone()
        conn.commit()
        conn.close()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Generate a new JWT token
        token = generate_token(user[0], user[1], user[3])
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'user_id': user[0],
                'username': user[1],
                'email': user[2],
                'role_id': user[3],
                'role_name': user[4] if len(user) > 4 else 'user'
            },
            'message': 'OTP verified successfully'
        })
        
    except Exception as e:
        logger.error(f'Error verifying OTP: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route('/api/verify-token', methods=['GET'])
@token_required
def verify_token():
    """Verify if the provided token is valid"""
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'No token provided or invalid token format'
            }), 401
            
        token = auth_header.split(' ')[1]
        
        # Decode the token to get user info
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
            
            # Get user from database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT user_id, username, email, role_id FROM Users WHERE user_id = ?', 
                (user_id,)
            )
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                return jsonify({
                    'success': False,
                    'error': 'User not found'
                }), 404
                
            # Return user data
            user_data = {
                'user_id': user[0],
                'username': user[1],
                'email': user[2],
                'role_id': user[3]
            }
            
            return jsonify({
                'success': True,
                'user': user_data
            })
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'success': False,
                'error': 'Token has expired'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'success': False,
                'error': 'Invalid token'
            }), 401
            
    except Exception as e:
        logger.error(f'Error verifying token: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=8100)
