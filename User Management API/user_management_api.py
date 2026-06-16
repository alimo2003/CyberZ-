from flask import Flask, request, jsonify, session, make_response
from flask_cors import CORS, cross_origin
import pyodbc
from datetime import datetime
import hashlib
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Enable CORS with more permissive settings for development
cors = CORS()
cors.init_app(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"],
        "supports_credentials": True,
        "expose_headers": ["Content-Type", "X-CSRFToken", "Content-Length", "*"],
        "max_age": 600
    }
}, supports_credentials=True)

# Handle preflight requests
@app.after_request
def after_request(response):
    # Add CORS headers to every response
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Database configuration
DB_CONFIG = {
    'DRIVER': 'ODBC Driver 17 for SQL Server',
    'SERVER': 'localhost\\SQLEXPRESS',
    'DATABASE': 'CyberZ',
    'Trusted_Connection': 'yes'
}

# Create connection string
CONN_STR = ';'.join(f"{k}={v}" for k, v in DB_CONFIG.items())

def get_db_connection():
    """Get a database connection."""
    try:
        conn = pyodbc.connect(CONN_STR)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

def row_to_dict(cursor, row):
    """Convert a pyodbc row to a dictionary."""
    return {column[0]: value for column, value in zip(cursor.description, row)}

# API Routes
@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Explicitly cast datetimeoffset to varchar to avoid type issues
        cursor.execute('''
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.first_name, 
                u.last_name, 
                u.is_active, 
                u.role_id, 
                CONVERT(VARCHAR, u.last_login, 120) as last_login,
                r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            ORDER BY u.username
        ''')
        
        # Get column names
        columns = [column[0] for column in cursor.description]
        
        # Convert rows to list of dictionaries
        users = []
        for row in cursor.fetchall():
            user = {}
            for i, col in enumerate(columns):
                # Convert any remaining datetime objects to ISO format
                if hasattr(row[i], 'isoformat'):
                    user[col] = row[i].isoformat()
                else:
                    user[col] = row[i]
            users.append(user)
        
        # Format the response to match frontend expectations
        formatted_users = []
        for user in users:
            formatted_users.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'is_active': bool(user['is_active']),  # Ensure boolean
                'role_id': user['role_id'],
                'role': user.get('role_name', 'User'),
                'last_login': user['last_login'] if user['last_login'] else None
            })
        
        return jsonify(formatted_users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a single user by ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Explicitly cast datetimeoffset to varchar to avoid type issues
        cursor.execute('''
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.first_name, 
                u.last_name, 
                u.is_active, 
                u.role_id, 
                CONVERT(VARCHAR, u.last_login, 120) as last_login,
                r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        
        if user is None:
            return jsonify({'error': 'User not found'}), 404
        
        # Convert row to dictionary with proper type handling
        columns = [column[0] for column in cursor.description]
        user_dict = {}
        for i, col in enumerate(columns):
            # Convert any remaining datetime objects to ISO format
            if hasattr(user[i], 'isoformat'):
                user_dict[col] = user[i].isoformat()
            else:
                user_dict[col] = user[i]
        
        # Format the response
        formatted_user = {
            'id': user_dict['id'],
            'username': user_dict['username'],
            'email': user_dict['email'],
            'first_name': user_dict['first_name'],
            'last_name': user_dict['last_name'],
            'is_active': bool(user_dict['is_active']),  # Ensure boolean
            'role_id': user_dict['role_id'],
            'role': user_dict.get('role_name', 'User'),
            'last_login': user_dict['last_login'] if user_dict['last_login'] else None
        }
        
        return jsonify(formatted_user)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user."""
    data = request.get_json()
    print("Received user data:", data)  # Log incoming data
    
    # Required fields validation
    required_fields = ['username', 'email', 'password', 'first_name', 'last_name', 'role_id']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        error_msg = f'Missing required fields: {", ".join(missing_fields)}'
        print(f"Validation error: {error_msg}")
        return jsonify({'error': error_msg}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Always hash the password on the server side with a new salt
        import uuid
        salt = str(uuid.uuid4()).replace('-', '')
        password_with_salt = data['password'] + salt
        password_hash = hashlib.sha256(password_with_salt.encode('utf-8')).hexdigest().upper()
        
        # Log the SQL query and parameters for debugging
        sql = '''
            INSERT INTO users (
                username, email, password_hash, salt,
                first_name, last_name, role_id,
                is_active, is_verified, created_at, updated_at
            )
            OUTPUT INSERTED.id
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, GETDATE(), GETDATE())
        '''
        params = (
            data['username'],
            data['email'],
            password_hash,
            salt,
            data['first_name'],
            data['last_name'],
            data['role_id']
        )
        
        print("Executing SQL:", sql)
        print("With parameters:", params)
        
        cursor.execute(sql, params)
        user_id = cursor.fetchval()
        conn.commit()
        
        if not user_id:
            error_msg = 'Failed to create user - no ID returned from database'
            print(error_msg)
            return jsonify({'error': error_msg}), 500
        
        # Get the newly created user with role name
        cursor.execute('''
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.first_name, 
                u.last_name, 
                u.is_active, 
                u.role_id, 
                CONVERT(VARCHAR, u.last_login, 120) as last_login,
                r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        
        # Convert row to dictionary with proper type handling
        columns = [column[0] for column in cursor.description]
        user_dict = {}
        for i, col in enumerate(columns):
            # Convert any remaining datetime objects to ISO format
            if user[i] is not None and hasattr(user[i], 'isoformat'):
                user_dict[col] = user[i].isoformat()
            else:
                user_dict[col] = user[i]
        
        # Format the response
        formatted_user = {
            'id': user_dict['id'],
            'username': user_dict['username'],
            'email': user_dict['email'],
            'first_name': user_dict['first_name'],
            'last_name': user_dict['last_name'],
            'is_active': bool(user_dict['is_active']),  # Ensure boolean
            'role_id': user_dict['role_id'],
            'role': user_dict.get('role_name', 'User'),
            'last_login': user_dict['last_login'] if user_dict['last_login'] else None
        }
        
        return jsonify(formatted_user), 201
    except pyodbc.IntegrityError as e:
        if 'UNIQUE' in str(e):
            return jsonify({'error': 'Username or email already exists'}), 400
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update an existing user."""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
        if not cursor.fetchone():
            return jsonify({'error': 'User not found'}), 404

        # Update user fields
        update_fields = []
        update_values = []

        # Only update password if provided
        if 'password' in data and data['password']:
            # Generate new salt and hash the password using the same method as login
            import uuid
            salt = str(uuid.uuid4()).replace('-', '')
            password_with_salt = data['password'] + salt
            password_hash = hashlib.sha256(password_with_salt.encode('utf-8')).hexdigest().upper()

            update_fields.extend(['password_hash = ?', 'salt = ?'])
            update_values.extend([password_hash, salt])

        # Update other fields
        for field in ['username', 'email', 'first_name', 'last_name', 'role_id']:
            if field in data:
                update_fields.append(f'{field} = ?')
                update_values.append(data[field])

        # Add updated_at timestamp
        update_fields.append('updated_at = GETDATE()')

        if not update_fields:
            return jsonify({'error': 'No fields to update'}), 400

        # Build and execute the update query
        update_query = f"""
            UPDATE users 
            SET {', '.join(update_fields)}
            WHERE id = ?
        """

        # Execute the update with user_id as the last parameter
        cursor.execute(update_query, (*update_values, user_id))
        conn.commit()

        # Get the updated user with role name
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.is_active, u.role_id, u.last_login,
                   r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = ?
        ''', (user_id,))

        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Failed to fetch updated user'}), 500
            
        # Convert row to dictionary with proper type handling
        columns = [column[0] for column in cursor.description]
        user_dict = {}
        for i, col in enumerate(columns):
            # Convert any remaining datetime objects to ISO format
            if user[i] is not None and hasattr(user[i], 'isoformat'):
                user_dict[col] = user[i].isoformat()
            else:
                user_dict[col] = user[i]
        
        # Format the response
        formatted_user = {
            'id': user_dict['id'],
            'username': user_dict['username'],
            'email': user_dict['email'],
            'first_name': user_dict['first_name'],
            'last_name': user_dict['last_name'],
            'is_active': bool(user_dict['is_active']),  # Ensure boolean
            'role_id': user_dict['role_id'],
            'role': user_dict.get('role_name', 'User'),
            'last_login': user_dict['last_login'] if user_dict['last_login'] else None
        }
        
        return jsonify(formatted_user)
    except pyodbc.IntegrityError as e:
        if 'UNIQUE' in str(e):
            return jsonify({'error': 'Username or email already exists'}), 400
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Handle CORS preflight for DELETE
@app.route('/api/users/<int:user_id>', methods=['OPTIONS'])
def handle_options(user_id):
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user by ID."""
    conn = None
    try:
        print(f"Received request to delete user {user_id}")
        
        # Get authorization header
        auth_header = request.headers.get('Authorization')
        print(f"Auth header: {'Present' if auth_header else 'Missing'}")
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user exists
        cursor.execute('SELECT id, username, role_id FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"User {user_id} not found")
            return jsonify({'error': 'User not found'}), 404
        
        print(f"Found user: {user.username} (ID: {user.id}, Role ID: {user.role_id})")
            
        # Get user's role
        cursor.execute('SELECT name FROM roles WHERE id = ?', (user.role_id,))
        role = cursor.fetchone()
        role_name = role[0].lower() if role else ''
        print(f"User role: {role_name}")
        
        # Check if this is a super admin (role_id = 1) which should never be deleted
        if user.role_id == 1:  # Assuming 1 is the super admin role ID
            # Check if there are other super admins before allowing deletion
            cursor.execute('''
                SELECT COUNT(*) as super_admin_count 
                FROM users 
                WHERE role_id = 1 AND id != ?
            ''', (user_id,))
            super_admin_count = cursor.fetchone().super_admin_count
            
            if super_admin_count == 0:
                error_msg = 'Cannot delete the last super admin user.'
                print(error_msg)
                return jsonify({'error': error_msg}), 403  # 403 Forbidden
                
        # For all other users including admins, allow deletion

        # Start a transaction
        try:
            # First, delete related MFA codes
            print(f"Deleting MFA codes for user {user_id}...")
            cursor.execute('DELETE FROM MFA_Codes WHERE user_id = ?', (user_id,))
            print(f"Deleted {cursor.rowcount} MFA codes")
            
            # Then delete the user
            print(f"Deleting user {user_id}...")
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            
            if cursor.rowcount == 0:
                error_msg = 'Failed to delete user - no rows affected'
                print(error_msg)
                conn.rollback()
                return jsonify({'error': error_msg}), 500
                
            conn.commit()
            success_msg = f'User {user.username} deleted successfully'
            print(success_msg)
            
        except Exception as e:
            conn.rollback()
            print(f"Error during user deletion: {str(e)}")
            return jsonify({
                'error': 'Failed to delete user due to database constraints',
                'details': str(e)
            }), 500
        
        return jsonify({
            'message': success_msg,
            'deleted_user_id': user_id
        })

    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({'error': 'An error occurred while deleting the user'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/roles', methods=['GET'])
def get_roles():
    """Get all roles."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Explicitly convert datetime to string in the SQL query
        cursor.execute('''
            SELECT 
                id, 
                name, 
                description, 
                CONVERT(VARCHAR, created_at, 120) as created_at
            FROM roles
            ORDER BY name
        ''')
        
        # Convert rows to list of dictionaries
        columns = [column[0] for column in cursor.description]
        roles = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return jsonify(roles)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5001)
