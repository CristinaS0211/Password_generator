from flask import Flask, render_template, request, jsonify, session
from cryptography.fernet import Fernet
import random, string, os, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure session key

# ----------------- Security Functions -----------------
def get_or_create_key():
    """Get encryption key or create if doesn't exist"""
    if not os.path.exists("master.key"):
        key = Fernet.generate_key()
        with open("master.key", "wb") as key_file:
            key_file.write(key)
        print(" New encryption key generated!")
    return open("master.key", "rb").read()

def encrypt_data(data):
    """Encrypt sensitive data"""
    key = get_or_create_key()
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def generate_secure_password(length=12, include_symbols=True):
    """Generate cryptographically secure password"""
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure at least one character from each category
    password = []
    password.append(secrets.choice(string.ascii_uppercase))
    password.append(secrets.choice(string.ascii_lowercase))
    password.append(secrets.choice(string.digits))
    if include_symbols:
        password.append(secrets.choice("!@#$%^&*"))
    
    # Fill remaining length with random choices
    for _ in range(length - len(password)):
        password.append(secrets.choice(chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

# ----------------- Routes -----------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            site = request.form.get("site", "").strip()
            length = int(request.form.get("length", 12))
            include_symbols = request.form.get("include_symbols") == "on"
            
            if length < 4 or length > 50:
                return render_template("index.html", error="Password length must be between 4 and 50")
            
            password = generate_secure_password(length, include_symbols)
            
            session_token = secrets.token_urlsafe(32)
            session[session_token] = password
            
            if site:
                encrypted_password = encrypt_data(password)
                try:
                    with open("secure_passwords.txt", "a", encoding='utf-8') as f:
                        import datetime
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"{timestamp} | {site} | {encrypted_password}\n")
                except Exception as e:
                    print(f"Warning: Could not save password: {e}")
            
            return render_template(
                "index.html",
                password_length=len(password),
                session_token=session_token,
                site_name=site,
                success=True
            )
            
        except Exception as e:
            print(f"Error generating password: {e}")
            return render_template("index.html", error="An error occurred generating the password")
    
    return render_template("index.html")

@app.route("/api/get-password", methods=["POST"])
def get_password():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token or token not in session:
            return jsonify({"success": False, "error": "Invalid or expired session"})
        
        password = session[token]
        return jsonify({"success": True, "password": password})
        
    except Exception as e:
        print(f"Error retrieving password: {e}")
        return jsonify({"success": False, "error": "Server error"})

@app.route("/api/password-strength", methods=["POST"])
def check_password_strength():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token or token not in session:
            return jsonify({"success": False, "error": "Invalid session"})
        
        password = session[token]
        
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 25
        else:
            feedback.append("Use at least 12 characters")
        
        if any(c.isupper() for c in password):
            score += 20
        else:
            feedback.append("Add uppercase letters")
            
        if any(c.islower() for c in password):
            score += 20
        else:
            feedback.append("Add lowercase letters")
            
        if any(c.isdigit() for c in password):
            score += 20
        else:
            feedback.append("Add numbers")
            
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 15
        else:
            feedback.append("Add special characters")
        
        if score >= 90:
            strength = "Very Strong"
            color = "#4caf50"
        elif score >= 70:
            strength = "Strong" 
            color = "#8bc34a"
        elif score >= 50:
            strength = "Medium"
            color = "#ff9800"
        else:
            strength = "Weak"
            color = "#f44336"
        
        return jsonify({
            "success": True,
            "score": score,
            "strength": strength,
            "color": color,
            "feedback": feedback
        })
        
    except Exception:
        return jsonify({"success": False, "error": "Error checking strength"})

# ----------------- Safe Run -----------------
if __name__ == "__main__":
    print(" SecurePass Pro - Professional Password Generator")
    print(" Encryption keys will be automatically generated")

    if os.environ.get("RENDER") or os.environ.get("PORT"):
        # 👉 Pe Render: aplicația e publică
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
    else:
        # 👉 Local: doar pentru tine
        app.run(host="127.0.0.1", port=5000, debug=True)
