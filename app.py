from flask import Flask, render_template, request
import re
import hashlib
import requests
import math
import logging
import os

app = Flask(__name__)

import re

# Password evaluation function
def evaluate_password(password):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Consider using 12+ characters for stronger protection.")
    else:
        feedback.append("Your password is very short. Longer passwords are safer.")

    # Uppercase check
    if re.search(r'[A-Z]', password):
        score += 2
    else:
        feedback.append("Add at least one uppercase letter (A-Z).")

    # Lowercase check
    if re.search(r'[a-z]', password):
        score += 2
    else:
        feedback.append("Add at least one lowercase letter (a-z).")

    # Numbers check
    if re.search(r'\d', password):
        score += 2
    else:
        feedback.append("Include at least one number (0-9).")

    # Special characters check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
    else:
        feedback.append("Use at least one special character (!@#$%^&*).")

    # Evaluate strength based on score
    if score >= 9:
        strength = "Very Strong"
    elif score >= 7:
        strength = "Strong"
    elif score >= 5:
        strength = "Medium"
    elif score >= 3:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return score, strength, feedback

# Breach check
def check_pwned_api(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "PasswordChecker/1.0"}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            logging.error(f"Pwned API returned status code {response.status_code}")
            return "API Error", -1

        hashes = (line.split(':') for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return True, int(count)
        return False, 0

    except Exception as e:
        logging.error(f"Pwned API request failed: {e}")
        return "API Error", -1

# Entropy/crack time
def estimate_crack_time(password):
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'\d', password): pool += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): pool += 32

    length = len(password)
    entropy = length * math.log2(pool) if pool > 0 else 0
    keyspace = pool ** length

    guesses_per_sec = 1_000_000_000
    time_sec = keyspace / guesses_per_sec

    return entropy, time_sec

@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("index.html")

@app.route('/check', methods=['POST'])
def check():
    password = request.form.get('password')

    if not password or len(password) < 8:
        return render_template('index.html', error="Password must be at least 8 characters long.")

    score, strength, feedback = evaluate_password(password)
    breached, count = check_pwned_api(password)
    entropy, crack_time = estimate_crack_time(password)

    return render_template('index.html',
                           password=password,
                           score=score,
                           strength=strength,
                           feedback=feedback,
                           breached=breached,
                           count=count,
                           entropy=entropy,
                           crack_time=crack_time)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
