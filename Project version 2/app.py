from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import mysql.connector
import random
import os
from datetime import datetime, date, timedelta

app = Flask(__name__)
app.secret_key = "super_secret_key_change_in_production"
bcrypt = Bcrypt(app)

# FERNET KEY

KEY_FILE = "fernet.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        key = f.read().strip()
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
cipher = Fernet(key)

# ADMIN CREDENTIALS
ADMIN_CREDENTIALS = {
    "Doorva_Sakpal": "24CC1015",
    "Arpita_Prasad": "24CC1006"
}
# 85% of admins must approve any sensitive proposal before it executes
ADMIN_APPROVAL_THRESHOLD = 0.85


# IP FIREWALL
blocked_ips     = set()
failed_attempts = {}
MAX_ATTEMPTS    = 5

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def firewall_check():
    ip = get_client_ip()
    if ip in blocked_ips:
        try:
            log_action(None, f"BLOCKED:{ip}", "FIREWALL_BLOCKED",
                       f"Blocked IP attempted access | IP: {ip}")
        except Exception:
            pass
        return False
    return True

def record_failed_attempt(ip):
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    if failed_attempts[ip] >= MAX_ATTEMPTS:
        blocked_ips.add(ip)
        try:
            log_action(None, f"AUTO-BLOCK:{ip}", "FIREWALL_AUTOBLOCK",
                       f"IP auto-blocked after {MAX_ATTEMPTS} failed login attempts")
        except Exception:
            pass

def reset_failed_attempts(ip):
    failed_attempts.pop(ip, None)

# DATABASE  ← UPDATE PASSWORD HERE

db_config = {
    "host":               "localhost",
    "user":               "root",
    "password":           "Doorva@151528",   # ← change if needed
    "database":           "test_db",
    "connection_timeout": 30,
    "autocommit":         False,
}

def get_db():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as e:
        print(f"[DB CONNECTION ERROR] {e}")
        raise


# HOME
@app.route('/')
def home():
    return render_template("voting.html")


# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if not firewall_check():
        flash("Access denied. Your IP has been blocked.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        full_name        = request.form.get('name', '').strip()
        email            = request.form.get('email', '').strip()
        phone_number     = request.form.get('phone', '').strip()
        aadhar_number    = request.form.get('aadhar', '')
        password         = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        voter_number     = request.form.get('voter', '').strip()
        date_of_birth    = request.form.get('dob', '').strip()
        state            = request.form.get('state', 'Maharashtra').strip()
        district         = request.form.get('district', '').strip()
        city             = request.form.get('city', '').strip()

        if not aadhar_number:
            flash("Aadhar number is required.", "danger")
            return redirect(url_for('register'))

        clean_aadhar = aadhar_number.replace(" ", "")
        if len(clean_aadhar) != 12 or not clean_aadhar.isdigit():
            flash("Aadhar number must be exactly 12 digits.", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for('register'))

        if date_of_birth:
            try:
                dob   = datetime.strptime(date_of_birth, "%Y-%m-%d").date()
                today = date.today()
                age   = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
                if age < 18:
                    flash("You must be at least 18 years old to register.", "danger")
                    return redirect(url_for('register'))
            except ValueError:
                flash("Invalid date of birth format.", "danger")
                return redirect(url_for('register'))

        conn   = get_db()
        cursor = conn.cursor(dictionary=True)

        # Check if Aadhar already registered
        cursor.execute("SELECT * FROM voter_accounts")
        all_users = cursor.fetchall()
        existing_aadhar_user = None
        for u in all_users:
            try:
                if cipher.decrypt(u['aadhar_number'].encode()).decode() == clean_aadhar:
                    existing_aadhar_user = u
                    break
            except Exception:
                continue

        if existing_aadhar_user:
            old_city     = existing_aadhar_user.get('city', '')
            old_district = existing_aadhar_user.get('district', '')
            old_state    = existing_aadhar_user.get('state', 'Maharashtra')
            if city.lower() != old_city.lower() or district.lower() != old_district.lower():
                session['address_change'] = {
                    "voter_id":      existing_aadhar_user['voter_id'],
                    "old_city":      old_city,
                    "old_district":  old_district,
                    "old_state":     old_state,
                    "new_city":      city,
                    "new_district":  district,
                    "new_state":     state,
                    "full_name":     full_name,
                    "email":         email,
                    "phone_number":  phone_number,
                    "aadhar_number": cipher.encrypt(clean_aadhar.encode()).decode(),
                    "password":      bcrypt.generate_password_hash(password).decode('utf-8'),
                    "voter_number":  voter_number,
                    "date_of_birth": date_of_birth
                }
                cursor.close()
                conn.close()
                return render_template("confirm_address_change.html",
                                       old_city=old_city, old_district=old_district,
                                       new_city=city, new_district=district,
                                       name=full_name)
            else:
                cursor.close()
                conn.close()
                flash("This Aadhar number is already registered in this area.", "danger")
                return redirect(url_for('register'))

        # Check duplicate email
        cursor.execute("SELECT voter_id FROM voter_accounts WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            flash("An account with this email already exists.", "danger")
            return redirect(url_for('register'))
        cursor.close()
        conn.close()

        pw_hash          = bcrypt.generate_password_hash(password).decode('utf-8')
        encrypted_aadhar = cipher.encrypt(clean_aadhar.encode()).decode()

        otp = random.randint(100000, 999999)
        session['otp'] = str(otp)
        print(f"[REGISTER OTP] {otp}")

        session['temp_user'] = {
            "full_name":     full_name,
            "email":         email,
            "phone_number":  phone_number,
            "aadhar_number": encrypted_aadhar,
            "password":      pw_hash,
            "voter_number":  voter_number,
            "date_of_birth": date_of_birth,
            "role":          "user",
            "state":         state,
            "district":      district,
            "city":          city,
        }

        flash(f"OTP sent! Check your console: {otp}", "info")
        return render_template("otp.html", mode="register")

    return render_template("register.html")



# ADDRESS CHANGE
@app.route('/confirm_address_change', methods=['POST'])
def confirm_address_change():
    data = session.get('address_change')
    if not data:
        flash("Session expired. Please try registering again.", "danger")
        return redirect(url_for('register'))

    voter_id = data['voter_id']
    conn     = get_db()
    cursor   = conn.cursor()

    cursor.execute("DELETE FROM vote_receipts WHERE voter_id = %s", (voter_id,))
    cursor.execute("DELETE FROM ballot_records WHERE voter_id = %s", (voter_id,))
    cursor.execute("DELETE FROM voter_accounts WHERE voter_id = %s", (voter_id,))
    conn.commit()

    log_action(voter_id, data['full_name'], "ADDRESS_CHANGE",
               f"Moved: {data['old_city']}/{data['old_district']} → {data['new_city']}/{data['new_district']}")

    cursor.execute("""
        INSERT INTO voter_accounts
            (full_name, email, phone_number, aadhar_number,
             password, voter_number, date_of_birth, role,
             state, district, city)
        VALUES (%s,%s,%s,%s,%s,%s,%s,'user',%s,%s,%s)
    """, (data['full_name'], data['email'], data['phone_number'],
          data['aadhar_number'], data['password'], data['voter_number'],
          data['date_of_birth'],
          data['new_state'], data['new_district'], data['new_city']))
    conn.commit()
    new_id = cursor.lastrowid
    cursor.close()
    conn.close()

    log_action(new_id, data['full_name'], "REGISTERED",
               f"Re-registered after address change. City: {data['new_city']} | District: {data['new_district']}")
    save_snapshot()
    session.pop('address_change', None)

    flash("Address updated. All old voting data cleared. Please login.", "success")
    return redirect(url_for('login'))



# OTP — REGISTER
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered_otp = request.form.get('otp', '').strip()
    if entered_otp == session.get('otp'):
        user = session.get('temp_user')
        if not user:
            flash("Session expired. Please register again.", "danger")
            return redirect(url_for('register'))

        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO voter_accounts
                (full_name, email, phone_number, aadhar_number,
                 password, voter_number, date_of_birth, role,
                 state, district, city)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (user['full_name'], user['email'], user['phone_number'],
              user['aadhar_number'], user['password'], user['voter_number'],
              user['date_of_birth'], user['role'],
              user.get('state', 'Maharashtra'),
              user.get('district', ''),
              user.get('city', '')))
        conn.commit()
        new_id = cursor.lastrowid
        cursor.close()
        conn.close()

        log_action(new_id, user['full_name'], "REGISTERED",
                   f"State: {user.get('state','')} | District: {user.get('district','')} | City: {user.get('city','')} | IP: {get_client_ip()}")
        save_snapshot()

        session.pop('otp', None)
        session.pop('temp_user', None)
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))

    flash("Invalid OTP. Please try again.", "danger")
    return redirect(url_for('register'))


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if not firewall_check():
        flash("Access denied. Your IP has been blocked due to too many failed attempts.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        aadhar_input = request.form.get('aadhar', '').replace(" ", "")
        password     = request.form.get('password', '')
        ip           = get_client_ip()

        conn   = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM voter_accounts")
        all_users = cursor.fetchall()
        cursor.close()
        conn.close()

        matched_user = None
        for u in all_users:
            try:
                if cipher.decrypt(u['aadhar_number'].encode()).decode() == aadhar_input:
                    matched_user = u
                    break
            except Exception:
                continue

        if matched_user and bcrypt.check_password_hash(matched_user['password'], password):
            reset_failed_attempts(ip)
            otp = random.randint(100000, 999999)
            session['login_otp'] = str(otp)
            session['user_id']   = matched_user['voter_id']
            session['user_role'] = matched_user['role']
            session['user_name'] = matched_user['full_name']
            session['user_city'] = matched_user.get('city', '')
            session['user_email']= matched_user.get('email', '')
            session['user_ip']   = ip
            print(f"[LOGIN OTP] {otp}")
            flash(f"OTP sent! Check your console: {otp}", "info")
            return render_template("otp.html", mode="login")

        record_failed_attempt(ip)
        remaining = max(0, MAX_ATTEMPTS - failed_attempts.get(ip, 0))
        log_action(None, f"Aadhar:{aadhar_input[:4]}****", "LOGIN_FAILED",
                   f"Invalid credentials | IP: {ip} | Attempts left: {remaining}")

        if ip in blocked_ips:
            flash("Your IP has been blocked after too many failed attempts.", "danger")
        else:
            flash(f"Invalid Aadhar number or password. {remaining} attempt(s) left before your IP is blocked.", "danger")

    return render_template("login.html")


# ADMIN LOGIN

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if not firewall_check():
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        ip       = get_client_ip()

        if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
            reset_failed_attempts(ip)
            session['logged_in'] = True
            session['user_role'] = 'admin'
            session['user_name'] = username
            session['user_id']   = None
            log_action(None, username, "ADMIN_LOGIN", f"Admin logged in | IP: {ip}")
            return redirect(url_for('admin_dashboard'))

        record_failed_attempt(ip)
        log_action(None, username or "unknown", "ADMIN_LOGIN_FAILED", f"Failed attempt | IP: {ip}")
        flash("Invalid admin username or password.", "danger")

    return render_template("admin_login.html")

# OTP — LOGIN
@app.route('/verify_login_otp', methods=['POST'])
def verify_login_otp():
    entered_otp = request.form.get('otp', '').strip()
    if entered_otp == session.get('login_otp'):
        session['logged_in'] = True
        session.pop('login_otp', None)
        log_action(session['user_id'], session['user_name'],
                   "LOGIN_SUCCESS",
                   f"OTP verified | IP: {session.get('user_ip', 'unknown')}")
        return redirect(url_for('dashboard'))

    flash("Invalid OTP. Please try again.", "danger")
    return redirect(url_for('login'))



# DASHBOARD
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        flash("Please login first.", "warning")
        return redirect(url_for('login'))

    conn   = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT b.party, b.party_full, r.receipt_number, r.expires_at
        FROM ballot_records b
        LEFT JOIN vote_receipts r ON b.vote_id = r.vote_id
        WHERE b.voter_id = %s
    """, (session['user_id'],))
    already_voted = cursor.fetchone()
    cursor.close()
    conn.close()

    receipt_valid = False
    if already_voted and already_voted.get('expires_at'):
        receipt_valid = datetime.now() < already_voted['expires_at']

    return render_template("dashboard.html",
                           user_name=session.get('user_name', 'Voter'),
                           already_voted=already_voted,
                           receipt_valid=receipt_valid)



# SUBMIT VOTE
@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Not logged in. Please login again."}), 401

    if not firewall_check():
        return jsonify({"status": "error", "message": "Access denied — IP blocked."}), 403

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"status": "error", "message": "Session error: user ID missing. Please logout and login again."}), 401

    data = request.get_json(silent=True)
    if not data or not data.get('party'):
        return jsonify({"status": "error", "message": "Invalid request — no party selected."}), 400

    ip = get_client_ip()

    conn   = None
    cursor = None
    try:
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)

        # Check already voted
        cursor.execute("""
            SELECT b.vote_id, r.receipt_number
            FROM ballot_records b
            LEFT JOIN vote_receipts r ON b.vote_id = r.vote_id
            WHERE b.voter_id = %s
        """, (user_id,))
        existing = cursor.fetchone()
        if existing:
            if existing.get('receipt_number'):
                return jsonify({"status": "ok", "receipt_number": existing['receipt_number']})
            # Vote exists but no receipt — generate one now
            voted_at       = datetime.now()
            receipt_number = "RCP-" + os.urandom(5).hex().upper()
            expires_at     = voted_at + timedelta(hours=24)
            cursor.execute(
                "INSERT IGNORE INTO vote_receipts "
                "(vote_id, voter_id, receipt_number, issued_at, expires_at, voter_ip) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (existing['vote_id'], user_id, receipt_number, voted_at, expires_at, ip)
            )
            conn.commit()
            return jsonify({"status": "ok", "receipt_number": receipt_number})

        # Get voter location
        cursor.execute("SELECT state, district, city FROM voter_accounts WHERE voter_id = %s", (user_id,))
        user_loc = cursor.fetchone()
        state    = (user_loc['state']    or 'Maharashtra') if user_loc else 'Maharashtra'
        district = (user_loc['district'] or '')            if user_loc else ''
        city     = (user_loc['city']     or '')            if user_loc else ''

        voted_at = datetime.now()
        cursor.execute(
            "INSERT INTO ballot_records "
            "(voter_id, party, party_full, voted_at, state, district, city) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (user_id, data['party'], data.get('party_full', ''), voted_at, state, district, city)
        )
        vote_id = cursor.lastrowid

        receipt_number = "RCP-" + os.urandom(5).hex().upper()
        expires_at     = voted_at + timedelta(hours=24)

        cursor.execute(
            "INSERT IGNORE INTO vote_receipts "
            "(vote_id, voter_id, receipt_number, issued_at, expires_at, voter_ip) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (vote_id, user_id, receipt_number, voted_at, expires_at, ip)
        )
        conn.commit()

        log_action(user_id, session.get('user_name', '?'), "VOTED",
                   f"Party: {data['party']} | State: {state} | District: {district} | "
                   f"City: {city} | Receipt: {receipt_number} | IP: {ip}")
        save_snapshot()

        return jsonify({"status": "ok", "receipt_number": receipt_number})

    except Exception as e:
        print(f"[SUBMIT_VOTE ERROR] {e}")
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

    finally:
        if cursor:
            try: cursor.close()
            except Exception: pass
        if conn:
            try: conn.close()
            except Exception: pass



# RECEIPT  ← CRITICAL — fully fixed
@app.route('/receipt/<receipt_number>')
def receipt(receipt_number):
    if not session.get('logged_in'):
        flash("Please login to view your receipt.", "danger")
        return redirect(url_for('login'))

    conn   = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT r.receipt_number, r.issued_at, r.expires_at, r.voter_ip,
               b.party, b.party_full, b.voted_at,
               b.state, b.district, b.city,
               v.full_name, v.voter_number, v.email
        FROM vote_receipts r
        JOIN ballot_records b ON r.vote_id  = b.vote_id
        JOIN voter_accounts v ON r.voter_id = v.voter_id
        WHERE r.receipt_number = %s AND r.voter_id = %s
    """, (receipt_number, session['user_id']))
    receipt_data = cursor.fetchone()
    cursor.close()
    conn.close()

    if not receipt_data:
        flash("Receipt not found or does not belong to your account.", "danger")
        return redirect(url_for('dashboard'))

    # FIX: compare naive datetimes consistently
    expires_at = receipt_data['expires_at']
    if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is not None:
        from datetime import timezone
        now = datetime.now(timezone.utc)
    else:
        now = datetime.now()

    if now > expires_at:
        flash("This receipt has expired (valid for 24 hours only).", "warning")
        return redirect(url_for('dashboard'))

    return render_template("receipt.html", r=receipt_data)


# RESULTS
@app.route('/results', methods=['GET', 'POST'])
def results():
    receipt_data = None
    error        = None

    conn   = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT party, party_full, COUNT(*) as cnt
        FROM ballot_records GROUP BY party, party_full ORDER BY cnt DESC
    """)
    party_rows  = cursor.fetchall()
    total_votes = sum(r['cnt'] for r in party_rows)
    top3        = party_rows[:3]
    cursor.close()
    conn.close()

    if request.method == 'POST':
        receipt_number = request.form.get('receipt_number', '').strip().upper()
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT r.receipt_number, r.issued_at, r.expires_at, r.voter_ip,
                   b.party, b.party_full, b.voted_at,
                   b.state, b.district, b.city,
                   v.full_name, v.voter_number
            FROM vote_receipts r
            JOIN ballot_records b ON r.vote_id  = b.vote_id
            JOIN voter_accounts v ON r.voter_id = v.voter_id
            WHERE r.receipt_number = %s
        """, (receipt_number,))
        receipt_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if not receipt_data:
            error = "Receipt number not found. Please check and try again."
        elif datetime.now() > receipt_data['expires_at']:
            error = "This receipt has expired. Receipts are valid for 24 hours only."
            receipt_data = None

    return render_template("results.html",
                           receipt_data=receipt_data, error=error,
                           party_rows=party_rows, total_votes=total_votes, top3=top3)


# ADMIN DASHBOARD
@app.route('/admin')
def admin_dashboard():
    if not session.get('logged_in') or session.get('user_role') != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('admin_login'))

    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM voter_accounts")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ballot_records")
    total_votes = cursor.fetchone()[0]

    turnout = round((total_votes / total_users * 100), 1) if total_users > 0 else 0

    cursor.execute("""
        SELECT party, party_full, COUNT(*) as cnt
        FROM ballot_records GROUP BY party, party_full ORDER BY cnt DESC
    """)
    party_rows        = cursor.fetchall()
    party_labels      = [r[0] for r in party_rows]
    party_full_names  = [r[1] for r in party_rows]
    party_counts      = [r[2] for r in party_rows]
    party_percentages = [round((c / total_votes * 100), 1) if total_votes > 0 else 0 for c in party_counts]

    leading_party      = party_labels[0]     if party_labels else "—"
    leading_party_full = party_full_names[0] if party_full_names else "—"
    leading_votes      = party_counts[0]     if party_counts else 0
    parties_with_votes = len(party_labels)

    cursor.execute("""
        SELECT state, district, city, COUNT(*) as cnt
        FROM ballot_records
        WHERE city IS NOT NULL AND city != ''
        GROUP BY state, district, city ORDER BY cnt DESC
    """)
    city_vote_rows = cursor.fetchall()
    city_labels    = [f"{r[2]}, {r[1]}" for r in city_vote_rows]
    city_counts    = [r[3] for r in city_vote_rows]

    cursor.execute("""
        SELECT state, district, city, COUNT(*) as cnt
        FROM voter_accounts
        WHERE city IS NOT NULL AND city != ''
        GROUP BY state, district, city ORDER BY cnt DESC
    """)
    reg_city_rows = cursor.fetchall()

    cursor.execute("""
        SELECT voter_name, action, detail, timestamp
        FROM admin_logs ORDER BY timestamp DESC LIMIT 100
    """)
    all_logs    = cursor.fetchall()
    recent_logs = all_logs[:20]

    cursor.execute("SELECT COUNT(*) FROM admin_logs WHERE action='LOGIN_SUCCESS'")
    login_success_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM admin_logs WHERE action='LOGIN_FAILED'")
    login_failed_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM admin_logs WHERE action='FIREWALL_BLOCKED'")
    firewall_blocked_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM admin_logs WHERE action='FIREWALL_AUTOBLOCK'")
    firewall_autoblock_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM voter_accounts
        WHERE voter_id NOT IN (SELECT voter_id FROM ballot_records) AND role='user'
    """)
    not_voted_count = cursor.fetchone()[0]

    try:
        cursor.execute("""
            SELECT p.proposal_id, p.proposed_by, p.action_type, p.action_detail,
                   p.proposed_at, p.status,
                   COUNT(a.approval_id) as approval_count
            FROM admin_proposals p
            LEFT JOIN admin_approvals a ON p.proposal_id = a.proposal_id AND a.approved = 1
            WHERE p.status = 'pending'
            GROUP BY p.proposal_id, p.proposed_by, p.action_type,
                     p.action_detail, p.proposed_at, p.status
        """)
        pending_proposals = cursor.fetchall()

        cursor.execute("""
            SELECT proposal_id FROM admin_approvals WHERE admin_name = %s
        """, (session.get('user_name'),))
        already_voted_proposals = {r[0] for r in cursor.fetchall()}
    except Exception as e:
        print(f"[PROPOSALS ERROR] {e}")
        pending_proposals       = []
        already_voted_proposals = set()

    total_admins = len(ADMIN_CREDENTIALS)
    needed       = max(1, round(total_admins * ADMIN_APPROVAL_THRESHOLD))

    cursor.close()
    conn.close()
    save_snapshot()

    return render_template("admin_dashboard.html",
        total_votes=total_votes, total_users=total_users,
        turnout=turnout, parties_with_votes=parties_with_votes,
        party_labels=party_labels, party_full_names=party_full_names,
        party_counts=party_counts, party_percentages=party_percentages,
        leading_party=leading_party, leading_party_full=leading_party_full,
        leading_votes=leading_votes,
        login_success_count=login_success_count,
        login_failed_count=login_failed_count,
        firewall_blocked_count=firewall_blocked_count,
        firewall_autoblock_count=firewall_autoblock_count,
        not_voted_count=not_voted_count,
        recent_logs=recent_logs, all_logs=all_logs,
        city_labels=city_labels, city_counts=city_counts,
        reg_city_rows=reg_city_rows,
        pending_proposals=pending_proposals,
        already_voted_proposals=already_voted_proposals,
        total_admins=total_admins, needed=needed,
        current_admin=session.get('user_name'),
        blocked_ips=list(blocked_ips),
    )


# ADMIN — PROPOSE
@app.route('/admin/propose', methods=['POST'])
def admin_propose():
    if not session.get('logged_in') or session.get('user_role') != 'admin':
        return jsonify({"status": "error"}), 403

    action_type   = request.form.get('action_type')
    action_detail = request.form.get('action_detail')
    proposed_by   = session.get('user_name')

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO admin_proposals (proposed_by, action_type, action_detail, proposed_at, status)
        VALUES (%s, %s, %s, %s, 'pending')
    """, (proposed_by, action_type, action_detail, datetime.now()))
    conn.commit()
    proposal_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO admin_approvals (proposal_id, admin_name, approved, voted_at)
        VALUES (%s, %s, 1, %s)
    """, (proposal_id, proposed_by, datetime.now()))
    conn.commit()
    cursor.close()
    conn.close()

    log_action(None, proposed_by, "PROPOSED_ACTION",
               f"Type: {action_type} | Detail: {action_detail}")
    flash("Proposal submitted. Other admins must approve before it executes.", "info")
    return redirect(url_for('admin_dashboard'))


# ADMIN — VOTE ON PROPOSAL

@app.route('/admin/vote_proposal', methods=['POST'])
def vote_proposal():
    if not session.get('logged_in') or session.get('user_role') != 'admin':
        return jsonify({"status": "error"}), 403

    proposal_id = int(request.form.get('proposal_id'))
    approved    = int(request.form.get('approved'))
    admin_name  = session.get('user_name')

    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT approval_id FROM admin_approvals
        WHERE proposal_id = %s AND admin_name = %s
    """, (proposal_id, admin_name))
    if cursor.fetchone():
        flash("You have already voted on this proposal.", "warning")
        cursor.close()
        conn.close()
        return redirect(url_for('admin_dashboard'))

    cursor.execute("""
        INSERT INTO admin_approvals (proposal_id, admin_name, approved, voted_at)
        VALUES (%s, %s, %s, %s)
    """, (proposal_id, admin_name, approved, datetime.now()))
    conn.commit()

    total_admins = len(ADMIN_CREDENTIALS)
    needed       = max(1, round(total_admins * ADMIN_APPROVAL_THRESHOLD))

    cursor.execute("SELECT COUNT(*) FROM admin_approvals WHERE proposal_id=%s AND approved=1", (proposal_id,))
    yes_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM admin_approvals WHERE proposal_id=%s", (proposal_id,))
    total_voted = cursor.fetchone()[0]

    if yes_count >= needed:
        cursor.execute("UPDATE admin_proposals SET status='approved' WHERE proposal_id=%s", (proposal_id,))
        conn.commit()
        flash(f"Proposal approved by {yes_count}/{total_admins} admins and will be executed.", "success")
        log_action(None, admin_name, "PROPOSAL_APPROVED",
                   f"Proposal #{proposal_id} reached {yes_count}/{total_admins} approvals")
    elif total_voted >= total_admins:
        cursor.execute("UPDATE admin_proposals SET status='rejected' WHERE proposal_id=%s", (proposal_id,))
        conn.commit()
        flash("Proposal rejected — not enough approvals.", "danger")
    else:
        remaining = total_admins - total_voted
        flash(f"Vote recorded. {yes_count}/{needed} approvals so far. {remaining} admin(s) yet to vote.", "info")

    cursor.close()
    conn.close()
    log_action(None, admin_name, "VOTED_ON_PROPOSAL",
               f"Proposal #{proposal_id} | Vote: {'YES' if approved else 'NO'}")
    return redirect(url_for('admin_dashboard'))



# ACCOUNT — VIEW
@app.route('/account')
def account():
    if not session.get('logged_in'):
        flash("Please login first.", "warning")
        return redirect(url_for('login'))
    verified  = session.get('account_verified', False)
    user_data = None
    if verified:
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM voter_accounts WHERE voter_id = %s", (session['user_id'],))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
    return render_template("account_settings.html",
                           user_name=session.get('user_name', 'Voter'),
                           verified=verified,
                           user=user_data,
                           otp_sent=session.get('account_otp_sent', False))


# ACCOUNT — VERIFY IDENTITY
@app.route('/account/verify', methods=['POST'])
def account_verify():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    password = request.form.get('password', '')

    conn   = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM voter_accounts WHERE voter_id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash("Account not found.", "danger")
        return redirect(url_for('account'))

    if bcrypt.check_password_hash(user['password'], password):
        otp = random.randint(100000, 999999)
        session['account_otp']      = str(otp)
        session['account_otp_sent'] = True
        print(f"[ACCOUNT OTP] {otp}")
        log_action(session['user_id'], session['user_name'], "ACCOUNT_VERIFY_OTP_SENT",
                   "OTP sent for account settings access")
        flash(f"OTP sent! Check console: {otp}", "info")
    else:
        flash("Incorrect password.", "danger")

    return redirect(url_for('account'))



# ACCOUNT — VERIFY OTP

@app.route('/account/verify_otp', methods=['POST'])
def account_verify_otp():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    entered = request.form.get('otp', '').strip()
    if entered == session.get('account_otp'):
        session['account_verified']  = True
        session['account_otp_sent']  = False
        session.pop('account_otp', None)
        log_action(session['user_id'], session['user_name'], "ACCOUNT_VERIFIED",
                   "Identity verified for account settings")
        flash("Identity verified. You may now edit your details.", "success")
    else:
        flash("Invalid OTP. Please try again.", "danger")

    return redirect(url_for('account'))



# ACCOUNT — UPDATE

@app.route('/account/update', methods=['POST'])
def account_update():
    if not session.get('logged_in') or not session.get('account_verified'):
        flash("Please verify your identity first.", "warning")
        return redirect(url_for('account'))

    full_name    = request.form.get('full_name', '').strip()
    phone_number = request.form.get('phone', '').strip()
    dob_str      = request.form.get('dob', '').strip()
    district     = request.form.get('district', '').strip()
    city         = request.form.get('city', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_pw   = request.form.get('confirm_password', '').strip()
    state        = 'Maharashtra'

    if dob_str:
        try:
            dob   = datetime.strptime(dob_str, "%Y-%m-%d").date()
            today = date.today()
            age   = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            if age < 18:
                flash("Date of birth indicates you are under 18 — update not allowed.", "danger")
                return redirect(url_for('account'))
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for('account'))

    conn   = get_db()
    cursor = conn.cursor()

    if new_password:
        if len(new_password) < 6:
            flash("New password must be at least 6 characters.", "danger")
            cursor.close(); conn.close()
            return redirect(url_for('account'))
        if new_password != confirm_pw:
            flash("Passwords do not match.", "danger")
            cursor.close(); conn.close()
            return redirect(url_for('account'))
        pw_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cursor.execute("""
            UPDATE voter_accounts
            SET full_name=%s, phone_number=%s, date_of_birth=%s,
                state=%s, district=%s, city=%s, password=%s
            WHERE voter_id=%s
        """, (full_name, phone_number, dob_str or None,
              state, district, city, pw_hash, session['user_id']))
    else:
        cursor.execute("""
            UPDATE voter_accounts
            SET full_name=%s, phone_number=%s, date_of_birth=%s,
                state=%s, district=%s, city=%s
            WHERE voter_id=%s
        """, (full_name, phone_number, dob_str or None,
              state, district, city, session['user_id']))

    conn.commit()
    cursor.close()
    conn.close()

    session['user_name'] = full_name
    session['user_city'] = city
    session.pop('account_verified', None)
    session.pop('account_otp_sent', None)

    log_action(session['user_id'], full_name, "ACCOUNT_UPDATED",
               f"Name: {full_name} | District: {district} | City: {city} | IP: {get_client_ip()}")
    save_snapshot()

    flash("Account details updated successfully!", "success")
    return redirect(url_for('dashboard'))



# ACCOUNT — DELETE
@app.route('/account/delete', methods=['POST'])
def account_delete():
    if not session.get('logged_in') or not session.get('account_verified'):
        flash("Please verify your identity first.", "warning")
        return redirect(url_for('account'))

    user_id   = session['user_id']
    user_name = session.get('user_name', '?')

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vote_receipts WHERE voter_id = %s", (user_id,))
    cursor.execute("DELETE FROM ballot_records WHERE voter_id = %s", (user_id,))
    cursor.execute("DELETE FROM voter_accounts WHERE voter_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    log_action(None, user_name, "ACCOUNT_DELETED",
               f"User deleted their own account | IP: {get_client_ip()}")
    save_snapshot()
    session.clear()
    flash("Your account has been permanently deleted.", "info")
    return redirect(url_for('home'))



# ACCOUNT — SAVE (legacy alias)
@app.route('/account/save', methods=['POST'])
def account_save():
    return account_update()



# LOGOUT

@app.route('/logout')
def logout():
    if session.get('user_id'):
        log_action(session.get('user_id'), session.get('user_name', '?'),
                   "LOGOUT", f"IP: {get_client_ip()}")
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('home'))



# HELPERS

def log_action(voter_id, voter_name, action, detail):
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO admin_logs (voter_id, voter_name, action, detail, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        """, (voter_id, voter_name, action, detail, datetime.now()))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[LOG ERROR] {e}")


def save_snapshot():
    try:
        conn   = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM voter_accounts")
        total_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM ballot_records")
        total_votes = cursor.fetchone()[0]
        turnout = round((total_votes / total_users * 100), 1) if total_users > 0 else 0
        cursor.execute("SELECT party, COUNT(*) as cnt FROM ballot_records GROUP BY party ORDER BY cnt DESC LIMIT 1")
        top = cursor.fetchone()
        leading_party = top[0] if top else None
        leading_votes = top[1] if top else 0
        cursor.execute("SELECT COUNT(*) FROM admin_logs WHERE action='LOGIN_SUCCESS'")
        login_success = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM admin_logs WHERE action='LOGIN_FAILED'")
        login_failed = cursor.fetchone()[0]
        cursor.execute("""
            SELECT COUNT(*) FROM voter_accounts
            WHERE voter_id NOT IN (SELECT voter_id FROM ballot_records) AND role='user'
        """)
        not_voted = cursor.fetchone()[0]
        cursor.execute("""
            INSERT INTO admin_snapshots
                (snapshot_time, total_users, total_votes, turnout_pct,
                 leading_party, leading_votes, login_success, login_failed, not_voted)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (datetime.now(), total_users, total_votes, turnout,
              leading_party, leading_votes, login_success, login_failed, not_voted))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[SNAPSHOT ERROR] {e}")



# MAHARASHTRA PLACES

MAHARASHTRA_PLACES = {
    "Mumbai City":     ["Churchgate", "Colaba", "Byculla", "Dadar", "Kurla",
                        "Chembur", "Dharavi", "Wadala", "Sion", "Matunga"],
    "Mumbai Suburban": ["Andheri", "Borivali", "Goregaon", "Malad", "Kandivali",
                        "Jogeshwari", "Vile Parle", "Santacruz", "Bandra",
                        "Ghatkopar", "Vikhroli", "Mulund", "Powai", "Juhu"],
    "Thane":           ["Thane", "Kalyan", "Dombivli", "Ulhasnagar", "Bhiwandi",
                        "Mira-Bhayandar", "Ambernath", "Badlapur", "Titwala", "Mumbra"],
    "Raigad":          ["Navi Mumbai", "Panvel", "Kharghar", "Alibag", "Pen",
                        "Uran", "Karjat", "Roha", "Mahad", "Shrivardhan"],
    "Pune":            ["Pune", "Pimpri", "Chinchwad", "Baramati", "Lonavala",
                        "Talegaon", "Hadapsar", "Kothrud", "Wakad", "Hinjewadi",
                        "Baner", "Aundh", "Khadki", "Kondhwa"],
    "Nashik":          ["Nashik", "Malegaon", "Igatpuri", "Sinnar", "Nandgaon",
                        "Manmad", "Yeola", "Deola", "Kalwan", "Chandwad",
                        "Niphad", "Dindori"],
    "Ahmednagar":      ["Ahmednagar", "Shrirampur", "Rahuri", "Kopargaon",
                        "Sangamner", "Nevasa", "Parner", "Pathardi",
                        "Shevgaon", "Karjat"],
    "Aurangabad":      ["Aurangabad", "Jalna", "Gangapur", "Kannad",
                        "Khuldabad", "Paithan", "Phulambri", "Sillod", "Vaijapur"],
    "Beed":            ["Beed", "Ambajogai", "Ashti", "Georai", "Kaij",
                        "Manjlegaon", "Parli", "Patoda", "Shirur", "Dharur"],
    "Nanded":          ["Nanded", "Ardhapur", "Bhokar", "Biloli", "Deglur",
                        "Dharmabad", "Hadgaon", "Kandhar", "Kinwat", "Loha",
                        "Mudkhed", "Mukhed", "Naigaon", "Umri"],
    "Osmanabad":       ["Osmanabad", "Tuljapur", "Omerga", "Paranda",
                        "Kalamb", "Bhoom", "Lohara", "Washi"],
    "Latur":           ["Latur", "Udgir", "Nilanga", "Ausa", "Chakur",
                        "Deoni", "Renapur", "Shirur Anantpal"],
    "Hingoli":         ["Hingoli", "Aundha Nagnath", "Basmath",
                        "Kalamnuri", "Sengaon"],
    "Parbhani":        ["Parbhani", "Gangakhed", "Jintur", "Manwath",
                        "Pathri", "Purna", "Selu", "Sonpeth"],
    "Nagpur":          ["Nagpur", "Wardha", "Kamptee", "Hingna", "Katol",
                        "Narkhed", "Parseoni", "Ramtek", "Saoner", "Umred"],
    "Amravati":        ["Amravati", "Achalpur", "Anjangaon", "Daryapur",
                        "Dhamangaon", "Morshi", "Warud", "Tiosa"],
    "Akola":           ["Akola", "Akot", "Balapur", "Barshitakli",
                        "Murtajapur", "Patur", "Telhara"],
    "Washim":          ["Washim", "Karanja", "Malegaon", "Mangrulpir",
                        "Manora", "Risod"],
    "Buldhana":        ["Buldhana", "Chikhli", "Deulgaon Raja",
                        "Jalgaon Jamod", "Khamgaon", "Lonar", "Malkapur",
                        "Mehkar", "Motala", "Nandura", "Shegaon",
                        "Sindkhed Raja"],
    "Yavatmal":        ["Yavatmal", "Arni", "Darwha", "Digras", "Ghatanji",
                        "Kalamb", "Kelapur", "Mahagaon", "Ner", "Pusad",
                        "Ralegaon", "Umarkhed", "Wani", "Zari-Jamni"],
    "Jalgaon":         ["Jalgaon", "Amalner", "Bhusawal", "Bodwad",
                        "Chalisgaon", "Chopda", "Dharangaon", "Erandol",
                        "Jamner", "Muktainagar", "Pachora", "Parola",
                        "Raver", "Yawal"],
    "Dhule":           ["Dhule", "Sakri", "Shirpur", "Sindkheda"],
    "Nandurbar":       ["Nandurbar", "Navapur", "Shahada", "Shirpur",
                        "Taloda", "Akkalkuwa", "Akrani"],
    "Kolhapur":        ["Kolhapur", "Ichalkaranji", "Kagal", "Karvir",
                        "Panhala", "Radhanagari", "Shahuwadi"],
    "Sangli":          ["Sangli", "Miraj", "Kupwad", "Atpadi", "Jat",
                        "Kadegaon", "Khanapur", "Palus", "Shirala",
                        "Tasgaon", "Walwa"],
    "Satara":          ["Satara", "Karad", "Wai", "Khatav", "Khandala",
                        "Koregaon", "Mahabaleshwar", "Man", "Patan",
                        "Phaltan"],
    "Solapur":         ["Solapur", "Barshi", "Pandharpur", "Akkalkot",
                        "Karmala", "Madha", "Malshiras", "Mangalvedhe",
                        "Mohol", "Sangola"],
    "Ratnagiri":       ["Ratnagiri", "Guhagar", "Chiplun", "Dapoli",
                        "Khed", "Lanja", "Mandangad", "Rajapur",
                        "Sangameshwar"],
    "Sindhudurg":      ["Sindhudurg", "Kankavli", "Kudal", "Malvan",
                        "Sawantwadi", "Vaibhavwadi", "Vengurla",
                        "Devgad", "Dodamarg"],
    "Bhandara":        ["Bhandara", "Lakhandur", "Lakhani", "Mohadi",
                        "Pauni", "Sakoli", "Tumsar"],
    "Gondia":          ["Gondia", "Amgaon", "Arjuni Morgaon", "Deori",
                        "Goregaon", "Salekasa", "Sadak Arjuni", "Tirora"],
    "Chandrapur":      ["Chandrapur", "Ballarpur", "Bhadravati",
                        "Brahmapuri", "Chimur", "Gondpipri", "Mul",
                        "Nagbhid", "Rajura", "Sindewahi", "Warora"],
    "Gadchiroli":      ["Gadchiroli", "Aheri", "Armori", "Bhamragad",
                        "Chamorshi", "Dhanora", "Etapalli", "Korchi",
                        "Kurkheda", "Mulchera", "Sironcha"],
}



# PLACES API
@app.route('/api/places')
def api_places():
    district = request.args.get('district', '').strip()

    if district:
        cities = MAHARASHTRA_PLACES.get(district, [])
        return jsonify({"district": district, "cities": cities})

    return jsonify({
        "state":     "Maharashtra",
        "districts": sorted(MAHARASHTRA_PLACES.keys()),
        "states":    ["Maharashtra"]
    })



# RUN
if __name__ == "__main__":
    app.run(debug=True)
