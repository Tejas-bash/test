import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded secret (BAD PRACTICE)
SECRET_KEY = "hardcoded_secret_123"  # CodeQL will flag this as a hardcoded secret

# Vulnerable function: SQL Injection
@app.route("/user/<user_id>")
def get_user(user_id):
    # UNSAFE: Directly concatenating user input into the SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return jsonify({"user": user})
        else:
            return "User not found", 404
    except Exception as e:
        return f"Database error: {e}", 500
    finally:
        conn.close()

# Vulnerable function: Output unsanitized user input
@app.route("/submit", methods=["POST"])
def submit():
    user_input = request.form.get("data")

    # UNSAFE: Directly including user input in the response without sanitization
    return f"You submitted: {user_input}"

# Vulnerable function: Command Injection
@app.route("/run", methods=["POST"])
def run_command():
    command = request.form.get("command")

    # UNSAFE: Running shell commands with user input
    import os
    os.system(command)  # CodeQL will flag this as insecure

    return "Command executed!"

# Insecure hash algorithm
@app.route("/hash", methods=["POST"])
def hash_data():
    data = request.form.get("data")

    # UNSAFE: Using MD5, which is a weak hashing algorithm
    import hashlib
    hashed = hashlib.md5(data.encode()).hexdigest()

    return jsonify({"hashed": hashed})

if __name__ == "__main__":
    app.run(debug=True)
