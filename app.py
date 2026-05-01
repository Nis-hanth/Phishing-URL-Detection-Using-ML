
from flask import Flask, render_template, request, redirect, session
import pandas as pd
import pickle
import re
from urllib.parse import urlparse
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pyttsx3
import threading
import webbrowser
import os
import csv
from werkzeug.security import generate_password_hash, check_password_hash

# 🔹 Load model
model = pickle.load(open("Decision_Tree_Model.pkl", "rb"))
y_test = pickle.load(open("y_test.pkl", "rb"))
y_pred = pickle.load(open("y_pred.pkl", "rb"))

app = Flask(__name__)
app.secret_key = "secret123"

# 🔹 USER CSV AUTO CREATE
USER_FILE = "users.csv"
if not os.path.exists(USER_FILE):
    with open(USER_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password", "email"])

# 🔹 HISTORY CSV AUTO CREATE
HISTORY_FILE = "history.csv"
if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["user", "url", "result"])

# 🔊 Voice
def speak(text):
    if session.get('voice', True):   # ✅ respect voice setting
        def run():
            engine = pyttsx3.init()
            engine.setProperty('rate', 160)
            engine.say(text)
            engine.runAndWait()
        threading.Thread(target=run).start()

# 🔹 SAVE HISTORY
def save_history(user, url, result):
    with open(HISTORY_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([user, url, result])

# 🔹 GET USER HISTORY
def get_user_history(user):
    data = []
    with open(HISTORY_FILE, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if row[0] == user:
                data.append(row)
    return data


# 🔐 REGISTER
import re
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None

    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password:
            error = "All fields are required"

        elif password != confirm_password:
            error = "Passwords do not match"

        # 🔥 UPDATED PASSWORD RULES
        elif len(password) < 6:
            error = "Password must be at least 6 characters"

        elif not re.search(r"[A-Z]", password):
            error = "Password must contain at least one uppercase letter"

        elif not re.search(r"[@#$!~%^&*]", password):
            error = "Password must contain at least one special symbol (@#$!~%^&*)"

        else:
            with open(USER_FILE, 'r') as file:
                reader = csv.reader(file)
                next(reader)

                for row in reader:
                    if row[0] == username:
                        error = "Username already exists"
                    elif len(row) > 2 and row[2] == email:
                        error = "Email already registered"

        if not error:
            with open(USER_FILE, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([username, password, email])
            speak("Registration successful")
            return redirect('/login?message=Registered Successfully')

    return render_template('register.html', error=error)
# 🔐 LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        with open(USER_FILE, 'r') as file:
            reader = csv.reader(file)
            next(reader)

            for row in reader:
                stored_username = row[0]
                stored_password = row[1]

                # 🔹 CHECK USER + HASHED PASSWORD
                if stored_username == username and stored_password == password:
                    session['user'] = username
                    speak("Login successful")
                    return redirect('/')

        return "Invalid Username or Password"

    return render_template('login.html')

# 🔐 LOGOUT (ONLY ONCE ✅)
@app.route('/logout')
def logout():
    session.pop('user', None)
    speak("Logged out")
    return redirect('/login')

# 🔹 HOME
@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/login')

    df = pd.read_csv('phishing_dataset.csv').sample(n=50)
    data = df.to_dict(orient='records')
    columns = df.columns.tolist()

    accuracy = round(accuracy_score(y_pred, y_test) * 100, 2)
    precision = round(precision_score(y_pred, y_test) * 100, 2)
    recall = round(recall_score(y_pred, y_test) * 100, 2)
    f1score = round(f1_score(y_pred, y_test) * 100, 2)

    return render_template('index.html',
                           data=data,
                           columns=columns,
                           accuracy=accuracy,
                           precision=precision,
                           recall=recall,
                           f1score=f1score,
                           user=session['user'])

# 🔹 FEATURE EXTRACTION
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path

    return [
        url.count('.'),
        len(url),
        url.count('-'),
        1 if '@' in url else 0,
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        1 if 'https' in hostname else 0,
        path.count('/'),
        len(path),
        len(re.findall(r'\d', url))
    ]







def explain_url(url):
    reasons = []

    if "https" not in url:
        reasons.append("Website does not use HTTPS")

    if "login" in url or "verify" in url:
        reasons.append("Contains phishing keywords (login/verify)")

    if "@" in url:
        reasons.append("Suspicious '@' symbol in URL")

    if len(url) > 75:
        reasons.append("URL is too long")

    return reasons



# 🔹 PREDICT
# 🔹 PREDICT
@app.route('/predict', methods=['POST'])
def predict():
    if 'user' not in session:
        return redirect('/login')

    df = pd.read_csv('phishing_dataset.csv').sample(n=50)
    data = df.to_dict(orient='records')
    columns = df.columns.tolist()

    accuracy = round(accuracy_score(y_pred, y_test) * 100, 2)
    precision = round(precision_score(y_pred, y_test) * 100, 2)
    recall = round(recall_score(y_pred, y_test) * 100, 2)
    f1score = round(f1_score(y_pred, y_test) * 100, 2)

    url = request.form.get('url')
    features = extract_features(url)
    result = int(model.predict([features])[0])

    result_text = "Safe" if result == 0 else "Not Safe"

    # ✅ SAVE HISTORY
    save_history(session['user'], url, result_text)

    # ✅ EXPLANATION (ONLY HERE)
    reasons = explain_url(url) if result == 1 else []

    # 🔊 Voice
    if result == 0:
        speak("This website is safe")
    else:
        speak("Warning unsafe website")

    # ✅ RETURN
    return render_template('index.html',
                           result=result,
                           url=url,
                           reasons=reasons,
                           data=data,
                           columns=columns,
                           accuracy=accuracy,
                           precision=precision,
                           recall=recall,
                           f1score=f1score,
                           user=session['user'])
# 🔹 OPEN WEBSITE
@app.route('/open')
def open_site():
    if 'user' not in session:
        return redirect('/login')

    url = request.args.get('url')

    if not url.startswith("http"):
        url = "https://" + url

    webbrowser.open(url)
    return redirect('/')

# 🔹 HISTORY PAGE
@app.route('/history')
def history():
    if 'user' not in session:
        return redirect('/login')

    data = get_user_history(session['user'])
    return render_template('history.html', data=data)
# 🔹 SETTINGS PAGE
@app.route('/settings')
def settings():
    if 'user' not in session:
        return redirect('/login')
    return render_template('settings.html')


# 🔹 CHANGE PASSWORD
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return redirect('/login')

    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')

    rows = []
    updated = False

    with open(USER_FILE, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)

        for row in reader:
            if row[0] == session['user'] and row[1] == old_password:
                row[1] = new_password
                updated = True
            rows.append(row)

    with open(USER_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)

    if updated:
        return redirect('/settings')
    else:
        return "Old password incorrect"


# 🔹 CLEAR HISTORY
@app.route('/clear_history')
def clear_history():
    if 'user' not in session:
        return redirect('/login')

    rows = []

    with open(HISTORY_FILE, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)

        for row in reader:
            if row[0] != session['user']:
                rows.append(row)

    with open(HISTORY_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)

    return redirect('/history')


# 🔹 VOICE TOGGLE
import requests
from flask import request, jsonify

@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()

        user_message = data.get('message')
        lang = data.get("lang", "en")

        # 🌐 Language mapping
        language_map = {
            "en": "English",
            "hi": "Hindi",
            "te": "Telugu",
            "ta": "Tamil",
            "kn": "Kannada"
        }

        selected_language = language_map.get(lang, "English")

        # 🧠 Force model language
        prompt = f"Reply ONLY in {selected_language}: {user_message}"

        # 🚀 Call Ollama API
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False
            },
            timeout=30
        )

        result = response.json()

        return jsonify({
            "reply": result.get("response", "No response")
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({
            "reply": "⚠️ Chatbot error"
        })
# 🔹 RUN
if __name__ == "__main__":
    app.run(debug=True)