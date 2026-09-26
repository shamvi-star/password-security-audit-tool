import uuid
from datetime import datetime 
from getpass import getpass

common_password = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "password123",
    "admin",
    "letmein",
    "welcome"
]

def detect_sequence(password):
    sequence_length = 4
    for i in range(len(password)-sequence_length+1):
        current = password[i:i + sequence_length] 
        increasing = True
        decreasing = True
        for j in range(len(current)-1):
            if ord(current[j+1]) != ord(current[j])+1:
                increasing = False
            if ord(current[j+1]) != ord(current[j])-1:
                decreasing = False
        if increasing or decreasing:
            return True
    return False

def check_password(password):
    session_id = "SESSION-"+uuid.uuid4().hex[:8].upper()
    score = 0
    weaknesses = []
    length = len(password)

    # Checking for predictable sequence
    has_sequence = detect_sequence(password)
    if has_sequence:
        print("RULE-008: Predictable sequence detected.")
        weaknesses.append("RULE-008: Predictable sequence")
    else:
        print("No obvious sequence detected.")

    # Checking for common passwords.
    if password.lower() in common_password:
        print("RULE-006: Common password detected.")
        weaknesses.append("RULE-006: Common Password.")
    else:
        print("Not a common password.")

    # Checking for repeated sequence.
    has_repetition = len(set(password)) == 1

    if has_repetition:
        print("RULE-007: Password contains only one repeated character.")
        weaknesses.append("RULE-007: Repeated Character.")
    else:
        print("No repetition.")

    # Checking the length of password.
    if length >= 8:
        print("Password length is sufficient.")
        score += 1
    else:
        print("RULE-001: Password is too short.")
        weaknesses.append("RULE-001: Password too short.")

    # Checking for uppercase and lowercase characters.
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)

    if has_uppercase:
        print("Password contains an uppercase.")
        score += 1
    else:
        print("RULE-002: Password has no uppercase.")
        weaknesses.append("RULE-002: Missing uppercase letter.")

    if has_lowercase:
        print("Password contains a lowercase.")
        score += 1
    else:
        print("RULE-003: Password has no lowercase letter.")
        weaknesses.append("RULE-003: Missing lowercase letter.")

    # Checking for numbers and special characters.
    has_digit = any(char.isdigit() for char in password)

    if has_digit:
        print("Password contains a number.")
        score += 1
    else:
        print("RULE-004: Password has no number.")
        weaknesses.append("RULE-004: Missing number.")

    has_special = any(not char.isalnum() for char in password)
    if has_special:
        print("Password contains a special character.")
        score += 1 
    else:
        print("RULE-005: Password has no special character.")
        weaknesses.append("RULE-005: Missing special character")

    # Checking for keyboard pattern
    keyboard_patterns = [
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "qwertyuiop",
        "asdfghjkl"
    ]

    has_keyboard_pattern = False
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            has_keyboard_pattern = True
            break

    if has_keyboard_pattern:
        print("RULE-009: Keyboard pattern detected.")
        weaknesses.append("RULE-009: Keyboard Pattern")
    else:
        print("✓ No obvious keyboard pattern detected.")

    # Generating strength score
    print("Password Strength Score:", score, "/5")
    if score <= 1:
        print("Strength: Very Weak")
    elif score == 2:
        print("Strength: Weak")
    elif score == 3:
        print("Strength: Moderate")
    elif score == 4:
        print("Strength: Strong")
    else:
        print("Strength: Very Strong")

    # Displaying the detected weaknesses
    if weaknesses:
        print("\nSecurity Weaknesses Detected: ")
        for weakness in weaknesses:
            print("-", weakness) # FIX: Print individual weakness item, not the entire list
    else:
        print("\nNo obvious weaknesses detected")

    # Determine security risk level
    if any(weakness.startswith("RULE-006") or weakness.startswith("RULE-007") for weakness in weaknesses):
        risk_level = "HIGH"
    elif any(weakness.startswith("RULE-008") or weakness.startswith("RULE-009") for weakness in weaknesses):
        risk_level = "MEDIUM"
    elif len(weaknesses) >= 2:
        risk_level = "MEDIUM"
    elif len(weaknesses) == 1:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"
    print("Security Risk Level: ", risk_level)

    # Generate security alert
    if weaknesses:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_id = "ALERT: " + uuid.uuid4().hex[:8].upper()
        event_type = "PASSWORD_SECURITY_VIOLATION"
        print("\n SECURITY ALERT")
        print("Alert ID: " + alert_id)
        print("Session ID: ", session_id)
        print("Timestamp: ", timestamp)
        print("Event: ", event_type)
        print("Source: Password Security Audit Tool")
        print("Category: Authentication Security")
        print("Severity:", risk_level)
        print("Status: ACTIVE")
        print("Number of detections:", len(weaknesses))
        print("Detection Rules:")
        
        # Open file once and cleanly write logs
        with open("security_alerts.log", "a") as log_file:
            for weakness in weaknesses:
                print("-", weakness)
                print("Description: One or more password security detection rules were triggered.")
                print("Recommended Action: Create a longer, unique, and less predictable password.")
                
                
                log_file.write(f"{timestamp}|{alert_id}|{session_id}|{event_type}|Password Security Audit Tool|{risk_level}|ACTIVE|{weakness}\n")
    else:
        print("\n No security alert generated.")

    print("\n==== AUDIT SUMMARY ====")
    print("Total rules triggered:", len(weaknesses)) # FIX: Added rule count display value
    print("Final risk level: ", risk_level)
    print("Alert generated: ", "YES" if weaknesses else "NO")

    if weaknesses:
        print("Alert ID:", alert_id)
        print("Session ID:", session_id)
        print("Log file: security_alerts.log")

if __name__ == "__main__":
    print("Password Security Audit Tool Engine Online. Press Ctrl+C to quit.\n")
    try:
        while True:
            password = getpass("Enter a password to audit: ")
            if not password:
                break
            check_password(password)
            print("-" * 50)
    except KeyboardInterrupt:
        print("\nExiting program dynamically. Monitoring complete.")
