# User Management API

A RESTful API for managing users, roles, and permissions in the Security System project.

## Features

- User management (CRUD operations)
- Role-based access control
- User authentication and session management
- Password reset functionality
- Secure password hashing
- CORS support

## Prerequisites

- Python 3.8+
- pip (Python package manager)

## Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd user-management-api
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix or MacOS:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   # On Windows:
   run.bat
   # Or manually:
   # set FLASK_APP=app.py
   # set FLASK_ENV=development
   # python -m flask run --port=5001
   
   # On Unix/MacOS:
   # export FLASK_APP=app.py
   # export FLASK_ENV=development
   # python -m flask run --port=5001
   ```
   
   The API will be available at `http://localhost:5001`

## API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/me` - Get current user info

### Users
- `GET /api/users` - Get all users
- `GET /api/users/<id>` - Get a specific user
- `POST /api/users` - Create a new user
- `PUT /api/users/<id>` - Update a user
- `DELETE /api/users/<id>` - Delete a user
- `PATCH /api/users/<id>/status` - Update user status (Active/Inactive)

### Roles
- `GET /api/roles` - Get all roles

## Default Admin User

A default admin user is created when the database is initialized:
- **Username:** admin
- **Password:** admin123

**Important:** Change the default admin password after first login.

## Configuration

The application is pre-configured with the following settings:

- **Database**: SQLite database stored at `instance/users.db`
- **Secret Key**: Default development key (change in production)
- **CORS**: Configured for `http://localhost:3000`

To modify these settings, edit the configuration section in `app.py`.

## Security Considerations

- Always use HTTPS in production
- Change the default secret key
- Implement rate limiting
- Keep dependencies up to date
- Use strong password policies

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
