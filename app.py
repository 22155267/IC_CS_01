# Enhanced Flask app with SHAREABLE LINKS for secure file sharing
# Files can be shared via WhatsApp, Email, SMS - no account needed!

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import os
import secrets

app = Flask(__name__)
app.secret_key = "supersecretkey_change_this_in_production"
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# ====== STORAGE ======
UPLOAD_FOLDER = "uploaded_files"
ENCRYPTED_FOLDER = "encrypted_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

users = {
    "testuser": generate_password_hash("password123")
}

files = []
file_id_counter = 1

# Store shareable links
share_links = {}

# =====================================================
# INDEX PAGE
# =====================================================
@app.route("/")
def index():
    # If already logged in, go to dashboard
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


# =====================================================
# REGISTER
# =====================================================
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return render_template("index.html", error="Username and password required")

    if username in users:
        return render_template("index.html", error="Username already exists")

    # Create user
    users[username] = generate_password_hash(password)
    
    # Set session
    session.permanent = True
    session["username"] = username
    
    print(f"✅ User registered: {username}")
    print(f"✅ Session set: {dict(session)}")

    return redirect(url_for("dashboard"))


# =====================================================
# LOGIN
# =====================================================
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    print(f"🔐 Login attempt for: {username}")

    if not username or not password:
        return render_template("index.html", error="Username and password required")

    if username not in users:
        return render_template("index.html", error="Invalid username or password")

    if not check_password_hash(users[username], password):
        return render_template("index.html", error="Invalid username or password")

    # Set session
    session.permanent = True
    session["username"] = username
    
    print(f"✅ Login successful: {username}")
    print(f"✅ Session set: {dict(session)}")

    return redirect(url_for("dashboard"))


# =====================================================
# DASHBOARD
# =====================================================
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        print("❌ No session found, redirecting to login")
        return redirect(url_for("index"))
    
    print(f"✅ Dashboard accessed by: {session['username']}")
    return render_template("dashboard.html", username=session["username"])


# =====================================================
# LOGOUT
# =====================================================
@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username", "Unknown")
    session.clear()
    print(f"🚪 User logged out: {username}")
    return redirect(url_for("index"))


# =====================================================
# GET FILE LIST
# =====================================================
@app.route("/api/files")
def get_files():
    if "username" not in session:
        print("❌ API call without session")
        return jsonify({"error": "Not authenticated"}), 401

    username = session["username"]
    owned = [f for f in files if f["owner"] == username]
    shared = [f for f in files if username in f.get("shared_with", [])]

    print(f"📁 Files for {username}: {len(owned)} owned, {len(shared)} shared")

    return jsonify({"owned": owned, "shared": shared})


# =====================================================
# UPLOAD + ENCRYPT FILE
# =====================================================
@app.route("/api/upload", methods=["POST"])
def upload_file():
    global file_id_counter

    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    original_filename = request.form.get("original_filename", file.filename)
    
    # Save encrypted file directly (already encrypted by browser)
    enc_filename = f"enc_{file_id_counter}_{original_filename}"
    enc_path = os.path.join(ENCRYPTED_FOLDER, enc_filename)
    
    file.save(enc_path)

    # Get file size
    file_size = os.path.getsize(enc_path)

    file_entry = {
        "id": file_id_counter,
        "original_filename": original_filename,
        "encrypted_filename": enc_filename,
        "owner": session["username"],
        "upload_date": datetime.now().isoformat(),
        "file_path": enc_path,
        "file_size": file_size,
        "shared_with": [],
        "share_links": []
    }

    files.append(file_entry)
    print(f"📤 File uploaded: {original_filename} by {session['username']}")
    file_id_counter += 1

    return jsonify({"message": "File encrypted & uploaded successfully"})


# =====================================================
# DOWNLOAD (Serve encrypted file)
# =====================================================
@app.route("/api/download/<int:file_id>")
def download_file(file_id):
    if "username" not in session:
        return "Not authenticated", 401

    username = session["username"]
    file = next((f for f in files if f["id"] == file_id), None)
    
    if not file:
        return "File not found", 404
    
    if file["owner"] != username and username not in file.get("shared_with", []):
        return "Access denied", 403

    return send_file(file["file_path"], as_attachment=True, download_name=file["encrypted_filename"])


# =====================================================
# DELETE FILE
# =====================================================
@app.route("/api/delete/<int:file_id>", methods=["DELETE"])
def delete_file(file_id):
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    global files
    file = next((f for f in files if f["id"] == file_id), None)
    if not file:
        return jsonify({"error": "File not found"}), 404

    if file["owner"] != session["username"]:
        return jsonify({"error": "Permission denied"}), 403

    try:
        if os.path.exists(file["file_path"]):
            os.remove(file["file_path"])
    except Exception as e:
        print(f"Error deleting file: {e}")

    # Remove associated share links
    file_links = file.get("share_links", [])
    for token in file_links:
        if token in share_links:
            del share_links[token]

    files = [f for f in files if f["id"] != file_id]
    print(f"🗑️ File deleted: {file['original_filename']}")

    return jsonify({"message": "File deleted"})


# =====================================================
# GENERATE SHAREABLE LINK
# =====================================================
@app.route("/api/share/link", methods=["POST"])
def generate_share_link():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    file_id = data.get("file_id")
    expiry_hours = data.get("expiry_hours", 24)
    
    if not file_id:
        return jsonify({"error": "Missing file_id"}), 400
    
    file = next((f for f in files if f["id"] == file_id), None)
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    if file["owner"] != session["username"]:
        return jsonify({"error": "Only file owner can generate links"}), 403
    
    # Generate unique token
    token = secrets.token_urlsafe(32)
    
    # Calculate expiry
    created_at = datetime.now()
    expires_at = created_at + timedelta(hours=expiry_hours)
    
    # Store link info
    share_links[token] = {
        "file_id": file_id,
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "download_count": 0,
        "created_by": session["username"]
    }
    
    # Add to file's share links
    if "share_links" not in file:
        file["share_links"] = []
    file["share_links"].append(token)
    
    # Generate shareable URL
    share_url = request.host_url + f"share/{token}"
    
    print(f"🔗 Share link created for: {file['original_filename']}")
    
    return jsonify({
        "success": True,
        "share_url": share_url,
        "token": token,
        "expires_at": expires_at.isoformat(),
        "expiry_hours": expiry_hours
    })


# =====================================================
# DOWNLOAD VIA SHAREABLE LINK (NO AUTH NEEDED!)
# =====================================================
@app.route("/share/<token>")
def download_shared_page(token):
    """Show download page with decryption instructions"""
    if token not in share_links:
        return "Invalid or expired link", 404
    
    link_info = share_links[token]
    
    # Check expiry
    expires_at = datetime.fromisoformat(link_info["expires_at"])
    if datetime.now() > expires_at:
        return "This link has expired", 410
    
    # Get file info
    file_id = link_info["file_id"]
    file = next((f for f in files if f["id"] == file_id), None)
    
    if not file:
        return "File not found", 404
    
    # Show download page
    return render_template("share_download.html",
                         token=token,
                         filename=file["original_filename"],
                         expiry=expires_at.strftime("%Y-%m-%d %H:%M"))


@app.route("/share/<token>/download")
def download_shared_file(token):
    """Download encrypted file (browser will decrypt it)"""
    
    if token not in share_links:
        return "Invalid or expired link", 404
    
    link_info = share_links[token]
    
    # Check expiry
    expires_at = datetime.fromisoformat(link_info["expires_at"])
    if datetime.now() > expires_at:
        return "This link has expired", 410
    
    # Get file
    file_id = link_info["file_id"]
    file = next((f for f in files if f["id"] == file_id), None)
    
    if not file:
        return "File not found", 404
    
    # Increment download counter
    share_links[token]["download_count"] += 1
    
    print(f"📥 Shared file downloaded: {file['original_filename']} (token: {token[:8]}...)")
    
    # Send encrypted file (browser will decrypt)
    return send_file(
        file["file_path"], 
        as_attachment=True,
        download_name=file["encrypted_filename"]
    )


# =====================================================
# GET ACTIVE SHARE LINKS FOR FILE
# =====================================================
@app.route("/api/file/<int:file_id>/links")
def get_file_share_links(file_id):
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    file = next((f for f in files if f["id"] == file_id), None)
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    if file["owner"] != session["username"]:
        return jsonify({"error": "Only owner can view links"}), 403
    
    # Get all active links for this file
    active_links = []
    for token in file.get("share_links", []):
        if token in share_links:
            link_info = share_links[token]
            expires_at = datetime.fromisoformat(link_info["expires_at"])
            
            active_links.append({
                "token": token,
                "url": request.host_url + f"share/{token}",
                "created_at": link_info["created_at"],
                "expires_at": link_info["expires_at"],
                "download_count": link_info["download_count"],
                "is_expired": datetime.now() > expires_at
            })
    
    return jsonify({"links": active_links})


# =====================================================
# REVOKE/DELETE SHARE LINK
# =====================================================
@app.route("/api/share/link/<token>", methods=["DELETE"])
def revoke_share_link(token):
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    if token not in share_links:
        return jsonify({"error": "Link not found"}), 404
    
    link_info = share_links[token]
    file_id = link_info["file_id"]
    
    file = next((f for f in files if f["id"] == file_id), None)
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    if file["owner"] != session["username"]:
        return jsonify({"error": "Only owner can revoke links"}), 403
    
    # Remove from share_links
    del share_links[token]
    
    # Remove from file's link list
    if "share_links" in file and token in file["share_links"]:
        file["share_links"].remove(token)
    
    print(f"🔗❌ Share link revoked: {token[:8]}...")
    
    return jsonify({"message": "Link revoked successfully"})


# =====================================================
# OLD SHARE METHOD (Keep for backward compatibility)
# =====================================================
@app.route("/api/share", methods=["POST"])
def share_file():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    file_id = data.get("file_id")
    share_with = data.get("share_with", "").strip()
    
    if not file_id or not share_with:
        return jsonify({"error": "Missing file_id or username"}), 400
    
    file = next((f for f in files if f["id"] == file_id), None)
    if not file:
        return jsonify({"error": "File not found"}), 404
    
    if file["owner"] != session["username"]:
        return jsonify({"error": "Only file owner can share"}), 403
    
    if share_with not in users:
        return jsonify({"error": f"User '{share_with}' not found"}), 404
    
    if share_with == session["username"]:
        return jsonify({"error": "Cannot share file with yourself"}), 400
    
    if "shared_with" not in file:
        file["shared_with"] = []
    
    if share_with in file["shared_with"]:
        return jsonify({"error": f"File already shared with {share_with}"}), 400
    
    file["shared_with"].append(share_with)
    
    return jsonify({
        "message": f"File shared with {share_with}",
        "shared_with": file["shared_with"]
    })


# =====================================================
# GET LIST OF ALL USERS
# =====================================================
@app.route("/api/users")
def get_users():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    current_user = session["username"]
    user_list = [{"username": u} for u in users.keys() if u != current_user]
    
    return jsonify({"users": user_list})


# =====================================================
# RUN
# =====================================================
if __name__ == "__main__":
    print("=" * 50)
    print("🚀 SecureShare Server Starting...")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)