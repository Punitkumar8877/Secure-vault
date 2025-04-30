from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from database import get_user, add_user, verify_user, hash_password, verify_password, update_password
from encryption import encrypt_file, decrypt_file
import os
import secrets
import itsdangerous  # For secure email tokens

app = Flask(__name__)
app.secret_key = "secure_vault_key"

# -------------------- MAIL CONFIGURATION --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True 
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'punitkproject78@gmail.com'
app.config['MAIL_PASSWORD'] = 'kwzs trus ikem xugs'
app.config['MAIL_DEFAULT_SENDER'] = 'punitkproject78@gmail.com'

mail = Mail(app)

# -------------------- TOKEN GENERATION --------------------
serializer = itsdangerous.URLSafeTimedSerializer(app.secret_key)

# -------------------- UPLOAD FOLDER --------------------
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------- ROUTES --------------------
# Home (Login Page)
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
       
        user = get_user(username)
        if user:
            if not user[4]:  # Email not verified
                flash("❌ Please verify your email before logging in.", "warning")
                return redirect(url_for("login"))

            if verify_password(password, user[2]):  # STEP 2: Use hashed password verification
                session["username"] = username
                session["role"] = user[5]  # Role: 'admin' or 'user'
                return redirect(url_for("dashboard"))
            else:
                flash("❌ Invalid username or password!", "danger")

    return render_template("login.html")

# Signup (User Registration)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        add_user(username, password, email)
        
        # STEP 3: Send email verification link
        send_verification_email(email)
        
        flash("✅ Signup successful! Please check your email to verify your account.", "info")
        return redirect(url_for("login"))

    return render_template("signup.html")

# Email Verification Route (STEP 3)
@app.route("/verify/<token>")
def verify(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)  # Token valid for 1 hour
        verify_user(email)
        flash("✅ Email verified successfully! You can now log in.", "success")
    except itsdangerous.SignatureExpired:
        flash("❌ Verification link expired. Please sign up again.", "danger")
    except itsdangerous.BadSignature:
        flash("❌ Invalid verification link.", "danger")

    return redirect(url_for("login"))

# Send Verification Email (STEP 3)
def send_verification_email(email):
    token = serializer.dumps(email, salt='email-confirm')
    verification_link = url_for("verify", token=token, _external=True)

    msg = Message("Verify Your Email - Secure Vault", recipients=[email])
    msg.body = f"Click the link below to verify your email:\n{verification_link}"

    try:
        mail.send(msg)
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Forgot Password Route
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        user = get_user(email)
        if user:
            send_reset_password_email(email)
            flash("✅ Password reset link sent to your email.", "info")
        else:
            flash("❌ No account found with this email.", "danger")

    return render_template("forgot_password.html")

# Password Reset Route
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, max_age=3600)  # Token valid for 1 hour
    except itsdangerous.SignatureExpired:
        flash("❌ Password reset link expired. Please try again.", "danger")
        return redirect(url_for("forgot_password"))
    except itsdangerous.BadSignature:
        flash("❌ Invalid password reset link.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        update_password(email, new_password)
        flash("✅ Password reset successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# Send Reset Password Email
def send_reset_password_email(email):
    token = serializer.dumps(email, salt='password-reset')
    reset_link = url_for("reset_password", token=token, _external=True)

    msg = Message("Reset Your Password", recipients=[email])
    msg.body = f"Click the link below to reset your password:\n{reset_link}"

    try:
        mail.send(msg)
        print(f"Reset password email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")
@app.route("/change_password", methods=["GET", "POST"])

# ---- ADD CHANGE PASSWORD ROUTE HERE --------------------

def change_password():
    if "username" not in session:
        flash("❌ Please log in to change your password.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        user = get_user(session["username"])

        if not verify_password(current_password, user[2]):  # Password check
            flash("❌ Incorrect current password.", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("❌ New passwords do not match.", "danger")
            return redirect(url_for("change_password"))

        update_password(user[3], new_password)  # Using email for lookup
        flash("✅ Password updated successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# Dashboard (User Portal)
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    shared_logs = get_user(session["username"])
    return render_template("dashboard.html", username=session["username"])

# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("✅ You have been logged out.", "info")
    return redirect(url_for("login"))

# File Upload for Encryption
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")

        # File Validation
        if not file or file.filename == '':
            flash("❌ No file selected. Please upload a valid file.", "danger")
            return redirect(url_for("upload"))

        # Save file securely
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
       
        # Encrypt the uploaded file
        encryption_key = encrypt_file(file_path)
        flash(f"✅ File '{filename}' encrypted successfully.", "success")
        return render_template("upload.html", filename=filename)

    return render_template("upload.html")

# File Decryption
@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == '':
            flash("❌ Please provide a valid filename.", "danger")
            return redirect(url_for("decrypt"))

        encrypted_path = os.path.join(UPLOAD_FOLDER, file.filename)
       
        if os.path.exists(encrypted_path):
            decrypt_file(encrypted_path)
            flash(f"✅ File '{file.filename}' decrypted successfully.", "success")
            return render_template("decrypt.html", filename=file.filename)
        else:
            flash(f"❌ File '{file.filename}' not found.", "danger")

    return render_template("decrypt.html")

# -------------------- RUN APP --------------------
if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
