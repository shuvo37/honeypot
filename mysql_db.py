
import mysql.connector
from datetime import datetime

def get_connection():
    """Create database connection with error handling"""
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="honeypot"
        )
        return conn
    except mysql.connector.Error as e:
        print(f"❌ Database connection error: {e}")
        return None

def log_attack(ip, username, password, protocol="SSH"):
    """Log SSH attack attempts"""
    conn = get_connection()
    if conn:
        try:
            c = conn.cursor()
            c.execute("INSERT INTO attacks (timestamp, ip_address, username, password, protocol) VALUES (%s, %s, %s, %s, %s)",
                      (datetime.now(), ip, username, password, protocol))
            conn.commit()
            print(f"[📝] Logged {protocol} attack from {ip}: {username}/{password}")
        except mysql.connector.Error as e:
            print(f"❌ Error logging attack: {e}")
        finally:
            conn.close()

def log_web_credentials(ip, username, password):
    """Log web form submissions"""
    conn = get_connection()
    if conn:
        try:
            c = conn.cursor()
            c.execute("INSERT INTO attacks (timestamp, ip_address, username, password, protocol) VALUES (%s, %s, %s, %s, 'WEB_FORM')",
                      (datetime.now(), ip, username, password))
            conn.commit()
            print(f"[🌐] Web credentials captured from {ip}: {username}/{password}")
        except mysql.connector.Error as e:
            print(f"❌ Error logging web credentials: {e}")
        finally:
            conn.close()

def ban_ip(ip, reason="Multiple failed attempts"):
    """Ban an IP address"""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO banned_ips (ip_address, reason, banned_at) VALUES (%s, %s, %s)",
                          (ip, reason, datetime.now()))
            conn.commit()
            print(f"[🚫] Successfully banned IP: {ip} - {reason}")
            return True
        except mysql.connector.IntegrityError:
            print(f"[ℹ️] IP {ip} is already banned")
            return False
        except mysql.connector.Error as e:
            print(f"[❌] Error banning IP {ip}: {e}")
            return False
        finally:
            conn.close()
    return False

def get_banned_ips():
    """Get all banned IPs"""
    conn = get_connection()
    if conn:
        try:
            c = conn.cursor()
            c.execute("SELECT * FROM banned_ips")
            ips = c.fetchall()
            return ips
        except mysql.connector.Error as e:
            print(f"❌ Error getting banned IPs: {e}")
            return []
        finally:
            conn.close()
    return []

def remove_ban(ip):
    """Remove IP from ban list AND reset its failure count"""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # Remove from banned_ips
            cursor.execute("DELETE FROM banned_ips WHERE ip_address = %s", (ip,))
            # Reset failure count
            cursor.execute("DELETE FROM ip_failures WHERE ip_address = %s", (ip,))
            conn.commit()
            print(f"[✅] Unbanned IP and reset failure count: {ip}")
            return True
        except mysql.connector.Error as e:
            print(f"❌ Error removing ban: {e}")
            return False
        finally:
            conn.close()
    return False

def get_all_attacks():
    """Retrieve all attacks from the database for analysis"""
    conn = get_connection()
    if conn:
        try:
            c = conn.cursor()
            c.execute("SELECT * FROM attacks ORDER BY timestamp DESC")
            attacks = c.fetchall()
            return attacks
        except mysql.connector.Error as e:
            print(f"❌ Error getting attacks: {e}")
            return []
        finally:
            conn.close()
    return []


# Add these functions to mysql_db.py

def get_failure_count(ip):
    """Get the current failure count for an IP"""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT failure_count FROM ip_failures WHERE ip_address = %s", (ip,))
            result = cursor.fetchone()
            return result[0] if result else 0
        except mysql.connector.Error as e:
            print(f"❌ Error getting failure count: {e}")
            return 0
        finally:
            conn.close()
    return 0


def increment_failure_count(ip):
    """Increment failure count for an IP"""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            # Use INSERT ... ON DUPLICATE KEY UPDATE
            cursor.execute("""
                INSERT INTO ip_failures (ip_address, failure_count, last_failure) 
                VALUES (%s, 1, %s)
                ON DUPLICATE KEY UPDATE 
                failure_count = failure_count + 1, 
                last_failure = %s
            """, (ip, datetime.now(), datetime.now()))
            conn.commit()

            # Get the updated count
            cursor.execute("SELECT failure_count FROM ip_failures WHERE ip_address = %s", (ip,))
            result = cursor.fetchone()
            return result[0] if result else 1
        except mysql.connector.Error as e:
            print(f"❌ Error incrementing failure count: {e}")
            return 1
        finally:
            conn.close()
    return 1


def reset_failure_count(ip):
    """Reset failure count when IP is unbanned"""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ip_failures WHERE ip_address = %s", (ip,))
            conn.commit()
            print(f"[✅] Reset failure count for IP: {ip}")
            return True
        except mysql.connector.Error as e:
            print(f"❌ Error resetting failure count: {e}")
            return False
        finally:
            conn.close()
    return False
