from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from math import ceil
from flask import flash
from flask import make_response
from flask_mysqldb import MySQL
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import io
import csv
import mysql.connector
import eventlet
import pandas as pd
import joblib
import pdfkit
import numpy as np
import os
import pymysql
import requests
import random
import string

app = Flask(__name__)
app.secret_key = "vcrab_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*")

# Database Configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "vcrab_db_final"
}

email_config = {
    "email": "",
    "password": "",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587
}

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e:
        print("Database connection error:", e)
        return None

def send_email(to, subject, text, html=None):
    try:
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = email_config["email"]
        msg['To'] = to
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text, 'plain')
        msg.attach(part1)
        
        if html:
            part2 = MIMEText(html, 'html')
            msg.attach(part2)
        
        # Create secure connection with server and send email
        with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
            server.ehlo()  # Can be omitted
            server.starttls()  # Secure the connection
            server.ehlo()  # Can be omitted
            server.login(email_config["email"], email_config["password"])
            server.send_message(msg)
        
        print(f"Email successfully sent to {to}")
        return True
    except Exception as e:
        print(f"Failed to send email to {to}. Error: {str(e)}")
        return False

@app.route('/verify-reset-code', methods=['GET', 'POST'])
def verify_reset_code():
    if request.method == 'POST':
        reset_code = request.form.get('reset_code')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if the reset code exists and has not expired
        cursor.execute("SELECT * FROM password_reset_codes WHERE reset_code = %s AND expires_at > %s", (reset_code, datetime.now()))
        reset_entry = cursor.fetchone()

        if not reset_entry:
            flash('Invalid or expired reset code', 'error')
            return redirect(url_for('forgot_password'))

        # Redirect to the reset password page with the code as a URL parameter
        return redirect(url_for('reset_password', reset_code=reset_code))

    return render_template('verify_reset_code.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    reset_code = request.args.get('reset_code')  # Retrieve the reset code from URL parameter
    if not reset_code:
        flash('Invalid or expired reset code', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', reset_code=reset_code))

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the password in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET password = %s
            WHERE id = (SELECT user_id FROM password_reset_codes WHERE reset_code = %s)
        """, (hashed_password, reset_code))
        conn.commit()

        # Remove the reset code from the database (it’s already used)
        cursor.execute("DELETE FROM password_reset_codes WHERE reset_code = %s", (reset_code,))
        conn.commit()

        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', reset_code=reset_code)



app.config['SECURITY_PASSWORD_SALT'] = 'vcrab_salt'  # Change this to a unique value

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        terms = request.form.get("terms")

        # Validate form data
        if not all([username, email, password, confirm_password, terms]):
            flash("All fields are required", "error")
            return redirect(url_for("register"))
            
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        # Password strength validation
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        if conn is None:
            flash("Database connection error. Please try again later.", "error")
            return redirect(url_for("register"))

        try:
            cursor = conn.cursor(dictionary=True)  # Use dictionary cursor
            
            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                flash("Username or email already exists", "error")
                return redirect(url_for("register"))

            # Insert new user
            cursor.execute("""
                INSERT INTO users (username, email, password, status, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, hashed_password, 'pending', 'user'))  # Changed role to 'user'
            
            conn.commit()

            # Notify admin about new registration
            cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
            admins = cursor.fetchall()
            for admin in admins:
                try:
                    send_email(
                        admin['email'],
                        "New User Registration",
                        f"A new user {username} ({email}) has registered and is awaiting approval."
                    )
                except Exception as e:
                    print(f"Failed to send email to admin: {e}")

            flash("Registration successful! Please wait for admin approval.", "success")
            return redirect(url_for("login"))

        except mysql.connector.Error as e:
            flash(f"Registration failed: {e}", "error")
            return redirect(url_for("register"))
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        if conn is None:
            return "Database connection error."
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["status"] != "approved":
                return "⛔ Your account is still pending admin approval."
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            return "Invalid credentials. Try again."

    return render_template("login.html")

@app.route("/admin/users")
def manage_users():
    if session.get("role") != "admin":
        return "Unauthorized access"

    page = int(request.args.get("page", 1))
    limit = 5
    offset = (page - 1) * limit

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM users WHERE status = 'pending'")
    total_users = cursor.fetchone()['total']
    total_pages = (total_users + limit - 1) // limit

    cursor.execute("""
        SELECT id, username, email, status 
        FROM users 
        WHERE status = 'pending' 
        ORDER BY id DESC 
        LIMIT %s OFFSET %s
    """, (limit, offset))
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin_users.html", users=users, page=page, total_pages=total_pages)

@app.route('/admin/export_users')
def export_pending_users():
    if session.get('role') != 'admin':
        return "Unauthorized"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username, email, status FROM users WHERE status = 'pending'")
    users = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Username', 'Email', 'Status'])
    writer.writerows(users)

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype="text/csv",
        as_attachment=True,
        download_name="pending_users.csv"
    )

@app.route("/admin/approve/<int:user_id>")
def approve_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    cursor.execute("UPDATE users SET status = 'approved' WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    if user:
        subject = "Your VCRAB Account Has Been Approved"
        message = f"""Hello {user['username']},
        
Your account for the VCRAB system has been approved by the administrator. 
You can now log in using your credentials.

Thank you,
VCRAB Team"""
        send_email(user['email'], subject, message)

    return redirect(url_for("manage_users"))

@app.route("/admin/reject/<int:user_id>")
def reject_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    cursor.execute("UPDATE users SET status = 'rejected' WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    if user:
        subject = "Your VCRAB Account Application"
        message = f"""Hello {user['username']},
        
We regret to inform you that your account application for the VCRAB system 
has been rejected by the administrator.

Thank you for your interest,
VCRAB Team"""
        send_email(user['email'], subject, message)

    return redirect(url_for("manage_users"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (session["username"],))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_email = request.form["email"]
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]

        hash_format_valid = user["password"].startswith("pbkdf2:sha256:")
        try:
            password_correct = check_password_hash(user["password"], current_password)
        except Exception as e:
            password_correct = False
            print("❌ Error checking password hash:", str(e))

        if not hash_format_valid or not password_correct:
            flash("Incorrect current password or invalid stored password format.", "danger")
        else:
            if new_email and new_email != user["email"]:
                cursor.execute("UPDATE users SET email = %s WHERE username = %s", (new_email, session["username"]))
            if new_password:
                hashed_pw = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, session["username"]))
            conn.commit()
            flash("Profile updated successfully.", "success")

            # Send email notification about profile change
            subject = "Your VCRAB Account Has Been Updated"
            message = f"""Hello {user['username']},
            
Your VCRAB account profile has been successfully updated. 
If you didn't make these changes, please contact the administrator immediately.

Thank you,
VCRAB Team"""
            send_email(user['email'] if 'email' in user else new_email, subject, message)

        cursor.execute("SELECT username, email, role, status FROM users WHERE username = %s", (session["username"],))
        user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("profile.html", user=user)

@app.route("/create_admin_user")
def create_admin_user():
    conn = get_db_connection()
    cursor = conn.cursor()

    username = "newadmin"
    email = "admin@example.com"
    password = generate_password_hash("admin", method="pbkdf2:sha256")
    status = "approved"
    role = "admin"

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing = cursor.fetchone()
    if existing:
        return "❗User already exists."

    try:
        cursor.execute("""
            INSERT INTO users (username, email, password, status, role)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, email, password, status, role))
        conn.commit()
        
        # Send welcome email to new admin
        subject = "Your VCRAB Admin Account"
        message = f"""Hello {username},
        
Your VCRAB admin account has been created successfully.
Username: {username}
Password: admin

Please change your password immediately after logging in.

Thank you,
VCRAB Team"""
        send_email(email, subject, message)
        
        return "✅ Admin user created! Username: newadmin | Password: admin"
    except Exception as e:
        return f"❌ Failed to insert admin: {e}"
    finally:
        cursor.close()
        conn.close()

import random
from datetime import datetime, timedelta
from flask import render_template, request, flash, redirect, url_for

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address', 'error')
            return redirect(url_for('forgot_password'))

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('forgot_password'))

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, email, username FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user:
                flash('Email address not found', 'error')
                return redirect(url_for('forgot_password'))

            # Generate a 6-digit reset code (numeric only)
            reset_code = ''.join(random.choices('0123456789', k=6))  # Numeric code only
            expires_at = datetime.now() + timedelta(hours=1)  # Set expiration time to 1 hour
            
            # Store the reset code in the database
            cursor.execute("""
                INSERT INTO password_reset_codes (user_id, reset_code, expires_at)
                VALUES (%s, %s, %s)
            """, (user['id'], reset_code, expires_at))
            conn.commit()

            # Send the reset code to the user's email
            subject = "Password Reset Code"
            message = f"""Hello {user['username']},

Here is your password reset code: {reset_code}.
It will expire in 1 hour.

If you did not request this, please ignore this email.

Thank you, Vcrab Team."""
            send_email(user['email'], subject, message)

            flash('A reset code has been sent to your email', 'success')
            return redirect(url_for('verify_reset_code'))  # Redirect to a page to input the reset code

        except Exception as e:
            flash(f'An error occurred. Please try again. {str(e)}', 'error')
            return redirect(url_for('forgot_password'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if conn:
                conn.close()

    return render_template('forgot_password.html')


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/controls") 
def controls():
    return render_template("control.html", username=session["username"])

@app.route("/monitoring")
def monitoring():
    return render_template("monitoring.html", username=session["username"])

@app.route("/reports")
def reports():
    return render_template("reports.html", username=session["username"])

@app.route("/notification")
def notification():
    return render_template("notification.html", username=session["username"])

@app.route('/analytics')
def analytics():
    return render_template("analytics.html", username=session.get("username"))

@app.route('/inventory')
def inventory():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    conn = get_db_connection()
    if conn is None:
        return "Database connection failed", 500
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM inventory ORDER BY date_harvested DESC LIMIT %s OFFSET %s", 
               (6, (page - 1) * 6))

        inventory_data = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) AS total FROM inventory")
        total_count = cursor.fetchone()['total']
        total_pages = (total_count + per_page - 1) // per_page
        
        cursor.execute("""
            SELECT 
                SUM(crab_count) AS total_crabs,
                SUM(CASE WHEN crab_gender = 'Male' THEN crab_count ELSE 0 END) AS male_count,
                SUM(CASE WHEN crab_gender = 'Female' THEN crab_count ELSE 0 END) AS female_count
            FROM inventory
        """)
        stats = cursor.fetchone()
        
        cursor.execute("SELECT SUM(crab_count) AS recent_harvest FROM inventory ")
        recent_harvest = cursor.fetchone()['recent_harvest'] or 0
        
        return render_template('inventory.html',
                               inventory=inventory_data,
                               page=page,
                               total_pages=total_pages,
                               total_crabs=stats['total_crabs'] or 0,
                               male_count=stats['male_count'] or 0,
                               female_count=stats['female_count'] or 0,
                               recent_harvest=recent_harvest,
                               username=session.get('username'))
    
    except Exception as e:
        return str(e), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/add_inventory", methods=["POST"])
def add_inventory():
    crab_gender = request.form["crab_gender"]
    crab_count = request.form["crab_count"]
    date_planted = request.form["date_planted"]
    date_harvested = request.form["date_harvested"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO inventory (crab_gender, crab_count, date_planted, date_harvested)
        VALUES (%s, %s, %s, %s)
    """, (crab_gender, crab_count, date_planted, date_harvested))
    conn.commit()
    cursor.close()
    conn.close()
    
    # Send inventory update notification to admins
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
    admins = cursor.fetchall()
    for admin in admins:
        send_email(
            admin['email'],
            "New Inventory Added",
            f"New inventory has been added:\n\n"
            f"Gender: {crab_gender}\n"
            f"Count: {crab_count}\n"
            f"Date Planted: {date_planted}\n"
            f"Date Harvested: {date_harvested}"
        )
    cursor.close()
    conn.close()
    
    return redirect(url_for("inventory"))

@app.route("/delete_inventory/<int:id>")
def delete_inventory(id):
    conn = get_db_connection()
    if conn is None:
        return "Database connection error."
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inventory WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for("inventory"))

@app.route("/fetch_inventory_chart_data")
def fetch_inventory_chart_data():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"})
    cursor = conn.cursor(dictionary=True)

    gender_counts = {"Male": 0, "Female": 0}
    harvest_over_time = {}

    try:
        cursor.execute("SELECT crab_gender, crab_count, date_harvested FROM inventory")
        rows = cursor.fetchall()

        for row in rows:
            gender = row["crab_gender"]
            count = row["crab_count"] or 0
            date = row["date_harvested"].strftime("%Y-%m-%d") if row["date_harvested"] else None

            if gender in gender_counts:
                gender_counts[gender] += count
            else:
                gender_counts[gender] = count

            if date:
                if date in harvest_over_time:
                    harvest_over_time[date] += count
                else:
                    harvest_over_time[date] = count

        return jsonify({
            "gender_counts": gender_counts,
            "harvest_over_time": harvest_over_time
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    
    # Send logout notification
    if username:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT email FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and user.get('email'):
                send_email(
                    user['email'],
                    "You Have Logged Out",
                    f"Hello {username},\n\nYou have successfully logged out of the VCRAB system."
                )
    
    return redirect(url_for("login"))

def insert_notification(device_id, message):
    conn = get_db_connection()
    if conn is None:
        print("Database connection error when inserting notification!")
        return
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notifications (device_id, message)
        VALUES (%s, %s)
    """, (device_id, message))
    conn.commit()
    cursor.close()
    conn.close()
    print(f"🔔 Notification inserted from {device_id}: {message}")

@app.route('/upload', methods=['POST'])
def upload_sensor_data():
    try:
        data = request.get_json()
        device_id = data.get("device_id", "unknown")
        temperature = data.get("temperature")
        ph_level = data.get("ph_level")
        tds_value = data.get("tds_value")
        turbidity = data.get("turbidity")

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB error"}), 500
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO sensor_readings (device_id, temperature, ph_level, tds_value, turbidity)
        VALUES (%s, %s, %s, %s, %s)
        """, (device_id, temperature, ph_level, tds_value, turbidity))
        conn.commit()

        if temperature is not None:
            if temperature < 24:
                insert_notification(device_id, "⚠️ Temp too low")
            elif temperature > 32:
                insert_notification(device_id, "⚠️ Temp too high")

        if ph_level is not None:
            if ph_level < 7.0:
                insert_notification(device_id, "⚠️ pH acidic")
            elif ph_level > 9.0:
                insert_notification(device_id, "⚠️ pH alkaline")

        if tds_value is not None and tds_value > 700:
            insert_notification(device_id, "⚠️ TDS too high")

        if turbidity is not None and turbidity > 150:
            insert_notification(device_id, "⚠️ Turbidity too high")

        cursor.close()
        conn.close()

        return jsonify({"message": "Inserted + checked"}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/notify", methods=["POST"])
def notify():
    try:
        data = request.get_json()
        device_id = data.get("device_id", "unknown")
        message = data.get("message")
        if not message:
            return jsonify({"error": "No message provided"}), 400

        insert_notification(device_id, message)
        return jsonify({"status": "Notification saved"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fetch_data")
def fetch_data():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"})
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sensor_readings ORDER BY timestamp DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()

    if result:
        socketio.emit("update_data", result)
        return jsonify(result)
    else:
        return jsonify({"message": "No sensor data available!"})

@app.route("/fetch_logs")
def fetch_logs():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"})
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT timestamp FROM sensor_readings ORDER BY timestamp DESC LIMIT 10")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(logs)

@app.route("/fetch_alerts")
def fetch_alerts():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"})
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10")
    alerts = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(alerts)

@app.route('/fetch_reports', methods=['GET'])
def fetch_reports():
    start_date = request.args.get('start', '')
    end_date = request.args.get('end', '')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"}), 500

    cursor = conn.cursor(dictionary=True)

    try:
        if start_date and end_date:
            query = """
            SELECT timestamp, temperature, ph_level, tds_value, turbidity
            FROM sensor_readings 
            WHERE DATE(timestamp) BETWEEN %s AND %s
            ORDER BY timestamp DESC
            """
            cursor.execute(query, (start_date, end_date))
        else:
            query = """
            SELECT timestamp, temperature, ph_level, tds_value, turbidity
            FROM sensor_readings 
            ORDER BY timestamp DESC
            """
            cursor.execute(query)

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)

    except mysql.connector.Error as e:
        print("Database Error:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/predict')
def predict():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM sensor_readings ORDER BY timestamp DESC LIMIT 1")
    latest = cursor.fetchone()

    if not latest:
        conn.close()
        return jsonify({"error": "No data available"}), 404

    cursor.execute("SELECT * FROM sensor_thresholds ORDER BY id DESC LIMIT 1")
    thresholds = cursor.fetchone()
    
    if not thresholds:
        conn.close()
        return jsonify({"error": "No threshold configuration found"}), 404

    crab_ranges = {
        "ph_level": {
            "safe": (thresholds["ph_min"], thresholds["ph_max"]),
            "warning_low": (max(0, thresholds["ph_min"] - 0.3), thresholds["ph_min"]),
            "warning_high": (thresholds["ph_max"], thresholds["ph_max"] + 0.3),
            "critical_low": (0, max(0, thresholds["ph_min"] - 0.3)),
            "critical_high": (thresholds["ph_max"] + 0.3, 14)
        },
        "tds_value": {
            "safe": (thresholds["tds_min"], thresholds["tds_max"]),
            "warning_low": (max(0, thresholds["tds_min"] - 5000), thresholds["tds_min"]),
            "warning_high": (thresholds["tds_max"], thresholds["tds_max"] + 5000),
            "critical_low": (0, max(0, thresholds["tds_min"] - 5000)),
            "critical_high": (thresholds["tds_max"] + 5000, 100000)
        },
        "turbidity": {
            "safe": (thresholds["turbidity_min"], thresholds["turbidity_max"]),
            "warning": (thresholds["turbidity_max"], thresholds["turbidity_max"] + 25),
            "critical": (thresholds["turbidity_max"] + 25, 1000)
        },
        "temperature": {
            "safe": (thresholds["temp_min"], thresholds["temp_max"]),
            "warning_low": (max(0, thresholds["temp_min"] - 2), thresholds["temp_min"]),
            "warning_high": (thresholds["temp_max"], thresholds["temp_max"] + 2),
            "critical_low": (0, max(0, thresholds["temp_min"] - 2)),
            "critical_high": (thresholds["temp_max"] + 2, 50)
        }
    }

    prediction = {}
    critical_count = 0
    warning_count = 0
    safe_count = 0
    advice = []

    for param, ranges in crab_ranges.items():
        val = latest[param]
        status = "Safe"
        advice_msg = f"{param.replace('_', ' ').capitalize()} is optimal for crabs"

        if param == "ph_level":
            if val < ranges["critical_low"][1]:
                status = "Critical"
                advice_msg = "Dangerously low pH! Can cause crab respiratory distress"
            elif val > ranges["critical_high"][0]:
                status = "Critical"
                advice_msg = "Dangerously high pH! Disrupts crab shell formation"
            elif ranges["warning_low"][0] <= val <= ranges["warning_low"][1]:
                status = "Warning"
                advice_msg = "Low pH may affect crab molting process"
            elif ranges["warning_high"][0] <= val <= ranges["warning_high"][1]:
                status = "Warning"
                advice_msg = "High pH may reduce crab feeding efficiency"

        elif param == "tds_value":
            if val < ranges["critical_low"][1]:
                status = "Critical"
                advice_msg = "Dangerously low salinity! Causes osmotic stress in crabs"
            elif val > ranges["critical_high"][0]:
                status = "Critical"
                advice_msg = "Dangerously high salinity! Leads to crab dehydration"
            elif ranges["warning_low"][0] <= val <= ranges["warning_low"][1]:
                status = "Warning"
                advice_msg = "Low salinity may reduce crab growth rate"
            elif ranges["warning_high"][0] <= val <= ranges["warning_high"][1]:
                status = "Warning"
                advice_msg = "High salinity may affect crab reproduction"

        elif param == "turbidity":
            if val > ranges["critical"][0]:
                status = "Critical"
                advice_msg = "Extreme turbidity! Risk of gill damage in crabs"
            elif ranges["warning"][0] <= val <= ranges["warning"][1]:
                status = "Warning"
                advice_msg = "High turbidity reduces crab feeding efficiency"

        elif param == "temperature":
            if val < ranges["critical_low"][1]:
                status = "Critical"
                advice_msg = "Dangerously cold! Crabs may become lethargic"
            elif val > ranges["critical_high"][0]:
                status = "Critical"
                advice_msg = "Dangerously hot! Risk of crab mortality"
            elif ranges["warning_low"][0] <= val <= ranges["warning_low"][1]:
                status = "Warning"
                advice_msg = "Cool temperatures may reduce crab metabolism"
            elif ranges["warning_high"][0] <= val <= ranges["warning_high"][1]:
                status = "Warning"
                advice_msg = "Warm temperatures may increase crab stress"

        if status == "Safe":
            safe_count += 1
        elif status == "Critical":
            critical_count += 1
        elif status == "Warning":
            warning_count += 1

        prediction[param] = {
            "value": val,
            "status": status,
            "advice": advice_msg
        }
        advice.append(advice_msg)

        if status in ["Warning", "Critical"]:
            cursor.execute("""
                INSERT INTO crab_notifications (parameter, value, status, advice, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (param, val, status, advice_msg, latest["timestamp"]))

    if critical_count > 0:
        overall_status = "Critical"
        # Send email alert for critical conditions
        subject = "CRITICAL ALERT: Crab Habitat Conditions"
        message = f"""Critical conditions detected in crab habitat at {latest["timestamp"]}:
        
- Overall Status: {overall_status}
- Score: {(safe_count * 100 + warning_count * 50) / len(crab_ranges):.1f}
        
Critical Parameters:
"""
        for param, data in prediction.items():
            if isinstance(data, dict) and data.get("status") == "Critical":
                message += f"- {param}: {data['value']} ({data['advice']})\n"

        cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
        admins = cursor.fetchall()
        for admin in admins:
            send_email(admin['email'], subject, message)
    elif warning_count > 0:
        overall_status = "Warning"
    else:
        overall_status = "Safe"

    total_params = len(crab_ranges) or 1
    overall_score = (safe_count * 100 + warning_count * 50) / total_params
    overall_score = round(overall_score, 1)

    prediction["timestamp"] = latest["timestamp"]
    prediction["overall_status"] = overall_status
    prediction["overall_score"] = overall_score  
    prediction["summary"] = advice

    cursor.execute("SELECT COUNT(*) AS count FROM predictive_analytics WHERE timestamp = %s", (latest["timestamp"],))
    if cursor.fetchone()["count"] == 0:
        insert_query = """
            INSERT INTO predictive_analytics (pH, tds, turbidity, temperature, overall_status, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            latest["ph_level"],
            latest["tds_value"],
            latest["turbidity"],
            latest["temperature"],
            overall_status,
            latest["timestamp"]
        ))

    conn.commit()
    conn.close()

    return jsonify(prediction)

@app.route('/api/notifications')
def get_crab_notifications():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, parameter, value, status, advice, timestamp, is_read 
        FROM crab_notifications 
        ORDER BY timestamp DESC 
        LIMIT 100
    """)
    notifications = cursor.fetchall()
    conn.close()
    return jsonify(notifications)

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_as_read(notification_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE crab_notifications 
        SET is_read = TRUE 
        WHERE id = %s
    """, (notification_id,))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/api/notifications/mark-all-read', methods=['POST'])
def mark_all_notifications_as_read():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE crab_notifications SET is_read = TRUE")
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/api/notifications', methods=['DELETE'])
def delete_all_notifications():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM crab_notifications")
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/get_thresholds', methods=["GET"])
def get_thresholds():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sensor_thresholds WHERE id = 1")
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(row)

@app.route('/set_thresholds', methods=["POST"])
def set_thresholds():
    data = request.get_json()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sensor_thresholds SET
            temp_min = %s, temp_max = %s,
            ph_min = %s, ph_max = %s,
            tds_min = %s, tds_max = %s,
            turbidity_min = %s, turbidity_max = %s
        WHERE id = 1
    """, (
        data['temp_min'], data['temp_max'],
        data['ph_min'], data['ph_max'],
        data['tds_min'], data['tds_max'],
        data['turbidity_min'], data['turbidity_max']
    ))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Thresholds updated successfully"})

@app.route('/download_csv', methods=['GET'])
def download_csv():
    start_date = request.args.get('start', '')
    end_date = request.args.get('end', '')

    if not start_date or not end_date:
        return jsonify({"error": "Both start and end dates are required"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"}), 500

    cursor = conn.cursor(dictionary=True)

    try:
        query = """
        SELECT timestamp, temperature, ph_level, tds_value, turbidity
        FROM sensor_readings 
        WHERE DATE(timestamp) BETWEEN %s AND %s
        ORDER BY timestamp DESC
        """
        cursor.execute(query, (start_date, end_date))
        rows = cursor.fetchall()

        if not rows:
            return jsonify({"error": "No data found for selected dates"}), 404

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Temperature (°C)', 'pH Level', 'TDS (ppm)', 'Turbidity (NTU)'])
        
        for row in rows:
            writer.writerow([
                row['timestamp'],
                row['temperature'],
                row['ph_level'],
                row['tds_value'],
                row['turbidity']
            ])
        
        output.seek(0)
        
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=sensor_data_{start_date}_to_{end_date}.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    except mysql.connector.Error as e:
        print("Database Error:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/fetch_history', methods=['GET'])
def fetch_history():
    time_range = request.args.get('range')

    if time_range == 'weekly':
        data = get_data_for_last_week()  
    elif time_range == 'monthly':
        data = get_data_for_last_month()  
    elif time_range == 'yearly':
        data = get_data_for_last_year() 
    else:
        data = []

    if not data:
        return jsonify({"message": "No data available for the selected time range."}), 404

    return jsonify(data)

def get_data_for_last_week():
    conn = get_db_connection()
    if conn is None:
        return []
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT DATE(timestamp) as date, 
               AVG(temperature) as avg_temp,
               AVG(ph_level) as avg_ph,
               AVG(tds_value) as avg_tds,
               AVG(turbidity) as avg_turbidity
        FROM sensor_readings
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return data

def get_data_for_last_month():
    conn = get_db_connection()
    if conn is None:
        return []
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT DATE(timestamp) as date, 
               AVG(temperature) as avg_temp,
               AVG(ph_level) as avg_ph,
               AVG(tds_value) as avg_tds,
               AVG(turbidity) as avg_turbidity
        FROM sensor_readings
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 MONTH)
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return data

def get_data_for_last_year():
    conn = get_db_connection()
    if conn is None:
        return []
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT MONTH(timestamp) as month, 
               AVG(temperature) as avg_temp,
               AVG(ph_level) as avg_ph,
               AVG(tds_value) as avg_tds,
               AVG(turbidity) as avg_turbidity
        FROM sensor_readings
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
        GROUP BY MONTH(timestamp)
        ORDER BY month
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return data

@app.route("/predict_next_3_hours")
def predict_next_3_hours():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="vcrab_db"
        )
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM sensor_readings ORDER BY timestamp DESC LIMIT 100")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        if not rows:
            return jsonify({"error": "No sensor data available."})

        df = pd.DataFrame(rows).sort_values(by="timestamp")
        X = df[["temperature", "ph_level", "tds_value", "turbidity"]]

        if "actual" in df.columns:
            accuracy = accuracy_score(df["actual"], df["prediction"])
        else:
            ground_truth = ((X["temperature"].between(25, 30)) &
                            (X["ph_level"].between(6.5, 7.5)) &
                            (X["tds_value"].between(400, 600)) &
                            (X["turbidity"] < 2.5)).astype(int)
            accuracy = accuracy_score(ground_truth, df["prediction"])

        latest = df.tail(10)
        data = [{
            "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "temperature": row["temperature"],
            "ph_level": row["ph_level"],
            "tds_value": row["tds_value"],
            "turbidity": row["turbidity"],
            "prediction": int(row["prediction"])
        } for _, row in latest.iterrows()]

        return jsonify({
            "result": "AI successfully analyzed upcoming risk based on last 10 data points.",
            "accuracy": round(accuracy * 100, 2),
            "data": data
        })

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    socketio.run(app, debug=True)
