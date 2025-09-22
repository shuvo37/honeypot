# analyzer.py
from collections import Counter
import re
import mysql_db  # Import your MySQL database functions


def analyze_logs():
    """
    Analyzes the honeypot attacks from MySQL database and prints a summary report.
    """
    print("\n" + "=" * 50)
    print("        HONEYPOT ATTACK ANALYSIS REPORT")
    print("=" * 50)

    try:
        # Get all attacks from MySQL database
        attacks = mysql_db.get_all_attacks()

        if not attacks:
            print("No attack data found in the database.")
            return

        # Extract data from database records
        ips, usernames, passwords, protocols = [], [], [], []

        for attack in attacks:
            # attack structure: (id, timestamp, ip_address, username, password, protocol, created_at)
            ips.append(attack[2])  # ip_address field
            usernames.append(attack[3])  # username field
            passwords.append(attack[4])  # password field
            protocols.append(attack[5])  # protocol field

        # Generate report
        print(f"📊 Total Attack Attempts: {len(ips)}")
        print(f"🌐 Unique Attacker IPs: {len(set(ips))}")
        print(f"👤 Unique Usernames Tried: {len(set(usernames))}")
        print(f"🔑 Unique Passwords Tried: {len(set(passwords))}")

        print("\n🎯 TOP 5 ATTACK PATTERNS:")
        print("\nTop 5 Usernames:")
        for user, count in Counter(usernames).most_common(5):
            print(f"  {user}: {count} attempts")

        print("\nTop 5 Passwords:")
        for pwd, count in Counter(passwords).most_common(5):
            print(f"  {pwd}: {count} attempts")

        print("\n🌐 Top 5 Suspicious IPs:")
        for ip, count in Counter(ips).most_common(5):
            print(f"  {ip}: {count} attempts")

        # Find common combinations
        if len(usernames) == len(passwords):
            combinations = [f"{u}/{p}" for u, p in zip(usernames, passwords)]
            print("\n🔗 Top 5 Username/Password Combinations:")
            for combo, count in Counter(combinations).most_common(5):
                print(f"  {combo}: {count} attempts")

    except Exception as e:
        print(f"❌ Error analyzing logs from database: {e}")


def analyze_by_protocol():
    """
    Additional analysis: Break down attacks by protocol
    """
    try:
        attacks = mysql_db.get_all_attacks()

        if not attacks:
            return

        protocols = [attack[5] for attack in attacks if attack[5]]  # protocol field

        print("\n📡 ATTACKS BY PROTOCOL:")
        for protocol, count in Counter(protocols).most_common():
            print(f"  {protocol}: {count} attempts")

    except Exception as e:
        print(f"❌ Error in protocol analysis: {e}")


def analyze_temporal_patterns():
    """
    Analyze attack patterns over time
    """
    try:
        attacks = mysql_db.get_all_attacks()

        if not attacks:
            return

        # Extract hours from timestamps
        hours = []
        for attack in attacks:
            timestamp = attack[1]  # timestamp field
            if timestamp:
                # Extract hour from datetime object
                if hasattr(timestamp, 'hour'):
                    hours.append(f"{timestamp.hour:02d}")
                else:
                    # If it's a string, extract using regex
                    hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', str(timestamp))
                    if hour_match:
                        hours.append(hour_match.group(1))

        print("\n⏰ ATTACKS BY HOUR:")
        for hour, count in Counter(hours).most_common(24):  # All 24 hours
            if count > 0:
                print(f"  {hour}:00 - {count} attacks")

    except Exception as e:
        print(f"❌ Error in temporal analysis: {e}")


if __name__ == "__main__":
    analyze_logs()
    analyze_by_protocol()
    analyze_temporal_patterns()
