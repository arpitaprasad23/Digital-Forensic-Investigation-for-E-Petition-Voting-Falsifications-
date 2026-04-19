This project report details the development of a Digital Forensic Investigation framework for e-petition and e-voting systems, designed to ensure election integrity through proactive security and verifiable evidence trails.
Developed by students at the Ramrao Adik Institute of Technology, the system addresses critical vulnerabilities in digital democracy, such as registration fraud, ballot stuffing, and administrative abuse.

Key Security FeaturesThe system implements a four-layer defense-in-depth strategy to prevent and detect falsifications:
Layer 1: Network Perimeter: An in-memory IP Firewall that monitors login attempts and automatically blacklists IPs after 5 consecutive failures to prevent brute-force attacks.
Layer 2: Multi-Factor Authentication: Registration and login require OTP verification and Aadhaar-based deduplication to ensure one voter, one account.
Layer 3: Data Security: Uses Fernet symmetric encryption (AES-128-CBC) for sensitive Aadhaar data and bcrypt for secure password hashing.
Layer 4: Administrative Consensus: A unique 70% supermajority approval mechanism is required for any sensitive administrative action (e.g., resetting data), preventing "insider attacks" by a single admin.

Technology UsedBack-end: Python programming language using Flask framework.
Database: MySQL database with immutable audit logs and UNIQUE constraint to ensure the “one-vote” rule.
Security: Fernet library, bcrypt, and one-time password verification mechanism.

Forensics “Forensically ready” design ensures that all electronic evidence can be admitted in court.
Immune Audit Logs: All actions from signing up to voting are tracked using exact timestamps and user identifiers.
Forensic Analytics: Real-time statistics on city or district-based vote counts to detect suspicious activities.
Receipt ID Verification: Vote receipts are delivered in ciphertext format to prove vote tallying while maintaining voter anonymity.

Project Setup Guide

This project uses a Virtual Environment (venv). This is not a library you "import," but a private folder that keeps the project's tools (like Flask and Bcrypt) separate from the rest of your computer.

1. Create the Virtual Environment
Open your terminal in this folder and run:
Windows: `python -m venv venv`
Mac/Linux: `python3 -m venv venv`

2. Activate the Environment
You must "enter" the environment so the computer knows to use the project's tools:
Windows (Command Prompt): `venv\Scripts\activate`
Windows (PowerShell): `.\venv\Scripts\activate`
Mac/Linux: `source venv/bin/activate`

Note: You should see `(venv)` appear at the start of your command line.

3. Install Required Libraries 

Once the environment is active, run this command to install everything needed (Flask, Bcrypt, MySQL connector, and Cryptography):
```bash
pip install flask flask-bcrypt cryptography mysql-connector-python
