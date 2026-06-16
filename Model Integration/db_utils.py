import pyodbc
import datetime

# Database connection string
CONN_STR = (
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=localhost\SQLEXPRESS;'  # Added SQLEXPRESS instance name
    'DATABASE=CyberZ;'
    'Trusted_Connection=yes;'
)

def get_db_connection():
    """Get a connection to the SQL Server database"""
    try:
        conn = pyodbc.connect(CONN_STR)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def test_connection():
    """Test the database connection"""
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT @@VERSION")
            version = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return True, version
        return False, "Could not establish connection"
    except Exception as e:
        return False, str(e)

# Attack logs functions
def insert_attack_log(attack_type, source_ip, payload, severity, status, user_agent=None, path=None, method=None):
    """Insert a new attack log into the database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        INSERT INTO AttackLogs 
        (Timestamp, AttackType, SourceIP, Payload, Severity, Status, UserAgent, Path, Method)
        VALUES (GETDATE(), ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        cursor.execute(query, (attack_type, source_ip, payload, severity, status, user_agent, path, method))
        conn.commit()
        
        # Get the ID of the inserted log
        cursor.execute("SELECT @@IDENTITY")
        log_id = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return log_id
    except Exception as e:
        print(f"Error inserting attack log: {e}")
        return None

def get_recent_attack_logs(limit=50):
    """Get recent attack logs from the database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT TOP (?) LogID, Timestamp, AttackType, SourceIP, Payload, Severity, Status, UserAgent, Path, Method
        FROM AttackLogs
        ORDER BY Timestamp DESC
        """
        
        cursor.execute(query, (limit,))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                "id": row[0],
                "timestamp": row[1].isoformat(),
                "type": row[2],
                "source_ip": row[3],
                "payload": row[4],
                "severity": row[5],
                "status": row[6],
                "user_agent": row[7],
                "path": row[8],
                "method": row[9]
            })
        
        cursor.close()
        conn.close()
        
        return logs
    except Exception as e:
        print(f"Error getting attack logs: {e}")
        return []

# Attack statistics functions
def update_attack_stats(timeframe, sqli_count, xss_count, blocked_count, detected_count):
    """Update attack statistics for a specific timeframe"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        UPDATE AttackStats
        SET SQLInjectionCount = ?, XSSCount = ?, BlockedCount = ?, DetectedCount = ?, LastUpdated = GETDATE()
        WHERE TimeframeType = ?
        """
        
        cursor.execute(query, (sqli_count, xss_count, blocked_count, detected_count, timeframe))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Error updating attack stats: {e}")
        return False

def get_attack_stats(timeframe):
    """Get attack statistics for a specific timeframe"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT SQLInjectionCount, XSSCount, BlockedCount, DetectedCount, LastUpdated
        FROM AttackStats
        WHERE TimeframeType = ?
        """
        
        cursor.execute(query, (timeframe,))
        row = cursor.fetchone()
        
        if row:
            stats = {
                "stats": {
                    "sqli": row[0],
                    "xss": row[1],
                    "blocked": row[2],
                    "detected": row[3]
                },
                "last_updated": row[4].isoformat(),
                "timeframe": timeframe
            }
        else:
            stats = {
                "stats": {
                    "sqli": 0,
                    "xss": 0,
                    "blocked": 0,
                    "detected": 0
                },
                "last_updated": datetime.datetime.now().isoformat(),
                "timeframe": timeframe
            }
        
        cursor.close()
        conn.close()
        
        return stats
    except Exception as e:
        print(f"Error getting attack stats: {e}")
        return {
            "stats": {
                "sqli": 0,
                "xss": 0,
                "blocked": 0,
                "detected": 0
            },
            "last_updated": datetime.datetime.now().isoformat(),
            "timeframe": timeframe,
            "error": str(e)
        }

# Model health functions
def insert_model_health(accuracy, precision_val, recall, f1_score, concept_drift, training_data_size):
    """Insert a new model health record"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        INSERT INTO ModelHealth 
        (Timestamp, Accuracy, Precision, Recall, F1Score, ConceptDrift, TrainingDataSize)
        VALUES (GETDATE(), ?, ?, ?, ?, ?, ?)
        """
        
        cursor.execute(query, (accuracy, precision_val, recall, f1_score, concept_drift, training_data_size))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Error inserting model health: {e}")
        return False

def get_latest_model_health():
    """Get the latest model health metrics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT TOP 1 MetricID, Timestamp, Accuracy, Precision, Recall, F1Score, ConceptDrift, TrainingDataSize
        FROM ModelHealth
        ORDER BY Timestamp DESC
        """
        
        cursor.execute(query)
        row = cursor.fetchone()
        
        if row:
            health = {
                "id": row[0],
                "timestamp": row[1].isoformat(),
                "accuracy": row[2],
                "precision": row[3],
                "recall": row[4],
                "f1_score": row[5],
                "concept_drift": row[6],
                "training_data_size": row[7]
            }
        else:
            health = None
        
        cursor.close()
        conn.close()
        
        return health
    except Exception as e:
        print(f"Error getting model health: {e}")
        return None

# Attack pattern functions
def update_hourly_attack_pattern(hour, sqli_count, xss_count):
    """Update hourly attack pattern data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        today = datetime.date.today()
        
        # Check if record exists for today and this hour
        query = """
        SELECT PatternID FROM HourlyAttackPatterns 
        WHERE Hour = ? AND RecordDate = ?
        """
        
        cursor.execute(query, (hour, today))
        row = cursor.fetchone()
        
        if row:
            # Update existing record
            query = """
            UPDATE HourlyAttackPatterns
            SET SQLInjectionCount = ?, XSSCount = ?
            WHERE Hour = ? AND RecordDate = ?
            """
            cursor.execute(query, (sqli_count, xss_count, hour, today))
        else:
            # Insert new record
            query = """
            INSERT INTO HourlyAttackPatterns
            (Hour, SQLInjectionCount, XSSCount, RecordDate)
            VALUES (?, ?, ?, ?)
            """
            cursor.execute(query, (hour, sqli_count, xss_count, today))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Error updating hourly attack pattern: {e}")
        return False

def update_daily_attack_pattern(day_of_week, sqli_count, xss_count):
    """Update daily attack pattern data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        today = datetime.date.today()
        
        # Check if record exists for today and this day of week
        query = """
        SELECT PatternID FROM DailyAttackPatterns 
        WHERE DayOfWeek = ? AND RecordDate = ?
        """
        
        cursor.execute(query, (day_of_week, today))
        row = cursor.fetchone()
        
        if row:
            # Update existing record
            query = """
            UPDATE DailyAttackPatterns
            SET SQLInjectionCount = ?, XSSCount = ?
            WHERE DayOfWeek = ? AND RecordDate = ?
            """
            cursor.execute(query, (sqli_count, xss_count, day_of_week, today))
        else:
            # Insert new record
            query = """
            INSERT INTO DailyAttackPatterns
            (DayOfWeek, SQLInjectionCount, XSSCount, RecordDate)
            VALUES (?, ?, ?, ?)
            """
            cursor.execute(query, (day_of_week, sqli_count, xss_count, today))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Error updating daily attack pattern: {e}")
        return False

def get_hourly_attack_patterns():
    """Get hourly attack patterns for the last 24 hours"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT Hour, SQLInjectionCount, XSSCount
        FROM HourlyAttackPatterns
        WHERE RecordDate >= DATEADD(day, -1, GETDATE())
        ORDER BY Hour
        """
        
        cursor.execute(query)
        patterns = []
        
        for row in cursor.fetchall():
            patterns.append({
                "hour": row[0],
                "sqli_count": row[1],
                "xss_count": row[2]
            })
        
        cursor.close()
        conn.close()
        
        return patterns
    except Exception as e:
        print(f"Error getting hourly attack patterns: {e}")
        return []

def get_daily_attack_patterns():
    """Get daily attack patterns for the last 7 days"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT DayOfWeek, SQLInjectionCount, XSSCount
        FROM DailyAttackPatterns
        WHERE RecordDate >= DATEADD(day, -7, GETDATE())
        ORDER BY DayOfWeek
        """
        
        cursor.execute(query)
        patterns = []
        
        for row in cursor.fetchall():
            patterns.append({
                "day": row[0],
                "sqli_count": row[1],
                "xss_count": row[2]
            })
        
        cursor.close()
        conn.close()
        
        return patterns
    except Exception as e:
        print(f"Error getting daily attack patterns: {e}")
        return []
