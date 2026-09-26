## Password Security Audit & Risk Detection Tool

## Oerview
The Password Security Audit & Risk Detection Tool is a beginner friendly cybersecurity project developed in Python. It analyzes passwords against multiple detection rules, assigns a risk level, generates security alerts, and records security events in a log file.
This project is designed as an introduction to security monitoring and SOC-style alert detection.

## Detection Rules
The tool checks for the following security issues:

RULE-001: Password is too short.
RULE-002: Missing uppercase letter.
RULE-003: Missing lowercase letter.
RULE-004: Missing number.
RULE-005: Missing special character.
RULE-006: Common password (like, Password123, etc.)
RULE-007: Repeated characters.
RULE-008: Predictable sequence.
RULE-009: Keyboard pattern.

## Risk level
The tool assigns a security risk level according to the number of rules detected:

MINIMAL: No security weakness detected.
LOW: One low level security weakness detected.
MEDIUM: Multiple weaknesses or predictale patterns detected.
HIGH: Common or repeated password patterns detected.

## Security Alerts
When one or more detection rules are triggered, the tool generates a security alert containing:
Alert ID
Session ID
Timestamp
Event Type
Source
Category
Severity
Status
Detection Rules Triggered

## Logging
Security events are recorded in 'security_alerts.log'.

Each log entry contains:
Timestamp
Alert ID
Session ID
Event Type
Source 
Severity
Status
Detection Rule Triggered

The log records security event information without storing the actual password.

## Technologies used:
Python
Python 'getpass' module
Python 'datetime' module
Python 'uuid' module
File handling for security event logging
VS Code

## Project Structure

Password Strength Checker
|
|---password_checker.py
|---security_alerts.log
|---README.md

## Working:-

1. The user enters a password securely using hidden inputs.
2. The tool checks the password against multiple detection rules.
3. Triggered rules are recorded as security weaknesses.
4. A password strength score is calculated.
5. A security risk level is assigned.
6. If weaknesses are detected, a security alert is generated.
7. Alert informations are recorded in 'security_alerts.log' file.
8. The tool returns to the input prompt for another audit
9. Press 'Ctrl+C' or 'Enter' to finish the execution.

## Example Detection
Password entered: Password123
Security Weaknesses Detected:
-RULE-006: Common Password
-RULE-005: Missing special character.
Security Risk Level: HIGH

## Future Improvements
Possible future improvements include:

Adding a larger compromised password database.
Exporting security reports.
Adding brute force attack detection based on repeated failed authentication attempts.
Integrating tools with a larger SOC monitoring system.

## Disclaimer

This project is intended for educational and cybersecurity learning purpose. The password strength score and detection rules are simplified rules and should not be treated as a complete password security assessment.
The tool does not store or log the actual password entered by the user.

## Author 
Shambhavi Bisht
Cybersecurity student interested in SOC operations, security monitoring, and threat detection.