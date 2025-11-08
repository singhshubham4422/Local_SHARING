import os
import sqlite3
import uuid
import shutil
import re
from datetime import datetime, timedelta
from PIL import Image
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
    jsonify,
    session,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
try:
    from flask_wtf import CSRFProtect
except Exception:
    CSRFProtect = None

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "data.db")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "txt", "pdf", "zip", "mp4", "mp3", "csv", "json"}
MAX_CONTENT_LENGTH = 50000 * 1024 * 1024  # 50 GB

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("LCD_SECRET", "dev-secret-key")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
# Session cookie hardening (adjust SESSION_COOKIE_SECURE via env when using HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Respect LCD_COOKIE_SECURE='1' or 'true' to enable Secure flag; avoid bool(...) on a string which is always True
secure_flag = os.environ.get('LCD_COOKIE_SECURE', '0').lower()
app.config['SESSION_COOKIE_SECURE'] = secure_flag in ('1', 'true', 'yes')
# Make sessions permanent by default with a reasonable lifetime so browsers retain the login cookie
app.permanent_session_lifetime = timedelta(days=7)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
# Enable CSRF protection if available
if CSRFProtect is not None:
    csrf = CSRFProtect(app)
else:
    csrf = None


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_online INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0
    )
    """
    )
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        original_name TEXT NOT NULL,
        size INTEGER,
        content_type TEXT,
        uploaded_at TEXT,
        original_owner_id INTEGER,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )
    """
    )
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        verb TEXT,
        details TEXT,
        created_at TEXT
    )
    """
    )
    # Ensure files.thumbnail column exists (for storing storage-relative thumbnail path)
    c.execute("PRAGMA table_info(files)")
    cols = [r[1] for r in c.fetchall()]
    if 'thumbnail' not in cols:
        try:
            c.execute("ALTER TABLE files ADD COLUMN thumbnail TEXT")
        except Exception:
            pass
    # ensure users.is_admin column exists (for older DBs)
    c.execute("PRAGMA table_info(users)")
    user_cols = [r[1] for r in c.fetchall()]
    if 'is_admin' not in user_cols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        except Exception:
            pass
    # Optionally create an admin user from environment variables
    admin_user = os.environ.get('LCD_ADMIN_USER')
    admin_pass = os.environ.get('LCD_ADMIN_PASS')
    if admin_user and admin_pass:
        c.execute('SELECT id FROM users WHERE username=?', (admin_user,))
        if not c.fetchone():
            from werkzeug.security import generate_password_hash
            c.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)', (admin_user, generate_password_hash(admin_pass)))
    # If no admin user exists yet, create a default admin/admin account per request
    c.execute('SELECT id FROM users WHERE is_admin=1 LIMIT 1')
    if not c.fetchone():
        # create default admin account username=admin password=admin (intentionally simple per user request)
        try:
            from werkzeug.security import generate_password_hash
            if not admin_user:
                default_admin_user = 'admin'
            else:
                default_admin_user = admin_user
            # use provided admin_pass if set, otherwise default to 'admin'
            default_admin_pass = admin_pass if admin_pass else 'admin'
            c.execute('SELECT id FROM users WHERE username=?', (default_admin_user,))
            if not c.fetchone():
                c.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)', (default_admin_user, generate_password_hash(default_admin_pass)))
        except Exception:
            pass
    conn.commit()
    conn.close()


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


class User(UserMixin):
    def __init__(self, id, username, password_hash, is_online=0):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_online = is_online
        self.is_admin = False

    @staticmethod
    def get_by_username(username):
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user = User(row["id"], row["username"], row["password_hash"], row["is_online"])
            user.is_admin = bool(row["is_admin"]) if 'is_admin' in row.keys() else False
            return user
        return None

    @staticmethod
    def get(user_id):
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        if row:
            user = User(row["id"], row["username"], row["password_hash"], row["is_online"])
            user.is_admin = bool(row["is_admin"]) if 'is_admin' in row.keys() else False
            return user
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def allowed_file(filename):
    # Allow any file type as long as a filename is provided.
    if not filename:
        return False
    # reject hidden files that start with a dot only
    if filename.startswith('.'):
        return False
    return True


def file_category(filename: str) -> str:
    """Return a category name for a filename based on its extension."""
    if not filename or '.' not in filename:
        return 'Other'
    ext = filename.rsplit('.', 1)[1].lower()
    images = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'tiff'}
    videos = {'mp4', 'mkv', 'avi', 'mov', 'webm', 'mpeg'}
    audio = {'mp3', 'wav', 'ogg', 'm4a', 'flac', 'aac'}
    docs = {'pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx', 'csv', 'md', 'html', 'htm', 'rtf'}
    archives = {'zip', 'rar', '7z', 'tar', 'gz'}
    code = {'py', 'js', 'ts', 'java', 'c', 'cpp', 'cs', 'rb', 'go', 'sh'}
    if ext in images:
        return 'Images'
    if ext in videos:
        return 'Videos'
    if ext in audio:
        return 'Audio'
    if ext in docs:
        return 'Documents'
    if ext in archives:
        return 'Archives'
    if ext in code:
        return 'Code'
    return 'Other'


def categorize_files(rows):
    """Group DB rows (files) into categories based on original_name."""
    categories = ['Documents', 'Images', 'Videos', 'Audio', 'Archives', 'Code', 'Other']
    grouped = {k: [] for k in categories}
    for r in rows:
        cat = file_category(r['original_name'])
        if cat not in grouped:
            grouped['Other'].append(r)
        else:
            grouped[cat].append(r)
    # return only non-empty categories in order
    return [(k, grouped[k]) for k in categories if grouped[k]]


def user_storage_dir(username):
    d = os.path.join(STORAGE_DIR, username)
    os.makedirs(d, exist_ok=True)
    return d


def safe_storage_path(relpath: str):
    """Return absolute path for a storage-relative path after sanitizing against traversal."""
    norm = os.path.normpath(os.path.join(STORAGE_DIR, relpath))
    if not norm.startswith(os.path.abspath(STORAGE_DIR)):
        # path traversal attempt
        raise ValueError("invalid path")
    return norm


def create_thumbnail_if_image(stored_path: str):
    """If stored_path is an image, create a small thumbnail in the user's .thumbs folder and
    return the storage-relative path to the thumbnail (e.g. 'alice/.thumbs/thumb_uuid.jpg').
    Otherwise return None."""
    try:
        # determine the storage-relative components
        abs_stored = os.path.abspath(stored_path)
        rel = os.path.relpath(abs_stored, STORAGE_DIR)
        parts = rel.split(os.sep)
        if len(parts) < 2:
            return None
        username = parts[0]
        stored_basename = os.path.basename(stored_path)
        thumb_dir = os.path.join(STORAGE_DIR, username, '.thumbs')
        os.makedirs(thumb_dir, exist_ok=True)
        thumb_name = f"thumb_{stored_basename}.jpg"
        thumb_path = os.path.join(thumb_dir, thumb_name)
        with Image.open(stored_path) as img:
            img.thumbnail((200, 200))
            img.convert('RGB').save(thumb_path, 'JPEG', quality=85)
        # return storage-relative path
        return os.path.join(username, '.thumbs', thumb_name).replace('\\', '/')
    except Exception:
        return None


def log_activity(user_id, verb, details=""):
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO activities (user_id, verb, details, created_at) VALUES (?, ?, ?, ?)",
        (user_id, verb, details, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


@app.template_filter('filesize')
def filesize_filter(num_bytes):
    """Format bytes as human-readable string in MB with 2 decimal places."""
    try:
        n = int(num_bytes)
    except Exception:
        return "-"
    mb = n / (1024 * 1024)
    if mb >= 1:
        return f"{mb:.2f} MB"
    kb = n / 1024.0
    if kb >= 1:
        return f"{kb:.2f} KB"
    return f"{n} B"


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password")
        if not username or not password:
            flash("Username and password required", "danger")
            return redirect(url_for("register"))
        # enforce a strict username whitelist to avoid filesystem/traversal issues
        if not re.match(r'^[A-Za-z0-9_.-]{3,32}$', username):
            flash("Invalid username — use 3-32 letters, numbers, dots, underscores or hyphens", "danger")
            return redirect(url_for("register"))
        if User.get_by_username(username):
            flash("Username already taken", "warning")
            return redirect(url_for("register"))
        pw_hash = generate_password_hash(password)
        conn = db_conn()
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
        conn.commit()
        conn.close()
        user_storage_dir(username)
        flash("Registration complete — please log in", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        user = User.get_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            # Clear any existing session to avoid session fixation attacks
            session.clear()
            login_user(user)
            # mark session as permanent so the session cookie gets an expiry (persists across browser restarts)
            session.permanent = True
            conn = db_conn()
            c = conn.cursor()
            c.execute("UPDATE users SET is_online=1 WHERE id=?", (user.id,))
            conn.commit()
            conn.close()
            log_activity(user.id, "login", f"User {username} logged in")
            flash("Logged in", "success")
            # If admin, redirect to admin dashboard
            if getattr(user, 'is_admin', False):
                return redirect(url_for('admin'))
            return redirect(url_for("index"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET is_online=0 WHERE id=?", (current_user.id,))
    conn.commit()
    conn.close()
    log_activity(current_user.id, "logout", f"User {current_user.username} logged out")
    logout_user()
    # clear session after logout to remove any residual data
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    conn = db_conn()
    c = conn.cursor()
    # My files (owner_id == current_user.id and original_owner_id IS NULL) — those I uploaded
    c.execute(
        "SELECT * FROM files WHERE owner_id=? AND original_owner_id IS NULL ORDER BY uploaded_at DESC",
        (current_user.id,),
    )
    my_files_rows = c.fetchall()
    # attach storage-relative path for each file row for templates to use
    my_files = []
    for r in my_files_rows:
        stored = r['stored_path']
        try:
            rel = os.path.relpath(os.path.abspath(stored), STORAGE_DIR).replace('\\', '/')
        except Exception:
            rel = ''
        d = dict(r)
        d['storage_rel'] = rel
        # determine category for icon/badges
        try:
            d['category'] = file_category(d['original_name'])
        except Exception:
            d['category'] = 'Other'
        # include thumbnail path if available
        d['thumbnail'] = r['thumbnail'] if 'thumbnail' in r.keys() else None
        my_files.append(d)
    grouped_my_files = categorize_files(my_files)
    # Shared With Me: files that were copied into my folder (original_owner_id IS NOT NULL)
    c.execute(
        "SELECT f.*, u.username as original_owner FROM files f LEFT JOIN users u ON f.original_owner_id = u.id WHERE f.owner_id=? AND f.original_owner_id IS NOT NULL ORDER BY f.uploaded_at DESC",
        (current_user.id,),
    )
    shared_rows = c.fetchall()
    shared_files = []
    for r in shared_rows:
        stored = r['stored_path']
        try:
            rel = os.path.relpath(os.path.abspath(stored), STORAGE_DIR).replace('\\', '/')
        except Exception:
            rel = ''
        d = dict(r)
        d['storage_rel'] = rel
        d['thumbnail'] = r['thumbnail'] if 'thumbnail' in r.keys() else None
        try:
            d['category'] = file_category(d['original_name'])
        except Exception:
            d['category'] = 'Other'
        shared_files.append(d)
    # All other users with online/offline status
    c.execute("SELECT id, username, is_online FROM users WHERE id!=? ORDER BY username COLLATE NOCASE", (current_user.id,))
    user_rows = c.fetchall()
    online_users = []
    for u in user_rows:
        online_users.append({
            'id': u['id'],
            'username': u['username'],
            'is_online': bool(u['is_online'])
        })
    conn.close()
    return render_template(
        "index.html",
        my_files_grouped=grouped_my_files,
        shared_files=shared_files,
        online_users=online_users,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        flash("No file part", "warning")
        return redirect(url_for("index"))
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No selected file", "warning")
        return redirect(url_for("index"))
    if not allowed_file(file.filename):
        flash("File type not allowed", "danger")
        return redirect(url_for("index"))
    original_name = file.filename
    ext = original_name.rsplit(".", 1)[1].lower() if "." in original_name else ""
    unique_name = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
    user_dir = user_storage_dir(current_user.username)
    stored_path = os.path.join(user_dir, unique_name)
    file.save(stored_path)
    size = os.path.getsize(stored_path)
    content_type = file.content_type
    # create thumbnail for images (stores in storage/<username>/.thumbs/ and returns rel path)
    try:
        thumb_rel = create_thumbnail_if_image(stored_path)
    except Exception:
        thumb_rel = None
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO files (owner_id, filename, stored_path, original_name, size, content_type, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            current_user.id,
            unique_name,
            stored_path,
            original_name,
            size,
            content_type,
            datetime.utcnow().isoformat(),
        ),
    )
    file_id = c.lastrowid
    if thumb_rel:
        # update DB with thumbnail path (storage-relative)
        c.execute("UPDATE files SET thumbnail=? WHERE id=?", (thumb_rel, file_id))
    conn.commit()
    conn.close()
    log_activity(current_user.id, "upload", original_name)
    flash("Upload successful", "success")
    return redirect(url_for("index"))


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, current_user.id))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("File not found or access denied", "danger")
        return redirect(url_for("index"))
    stored_path = row["stored_path"]
    owner_dir = os.path.dirname(stored_path)
    filename = row["filename"]
    # Flask <2.0 uses 'attachment_filename' while >=2.0 uses 'download_name'.
    # Try the modern param first, fall back for older Flask versions to avoid TypeError (server 500).
    try:
        return send_from_directory(owner_dir, filename, as_attachment=True, download_name=row["original_name"])
    except TypeError:
        return send_from_directory(owner_dir, filename, as_attachment=True, attachment_filename=row["original_name"])


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share(file_id):
    to_username = request.form.get("to_username", "").strip()
    if not to_username:
        flash("Please specify a recipient username", "warning")
        return redirect(url_for("index"))
    recipient = User.get_by_username(to_username)
    if not recipient:
        flash("Recipient not found", "danger")
        return redirect(url_for("index"))
    conn = db_conn()
    c = conn.cursor()
    # find original file (must belong to current user)
    c.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, current_user.id))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("File not found or access denied", "danger")
        return redirect(url_for("index"))
    src_path = row["stored_path"]
    if not os.path.exists(src_path):
        conn.close()
        flash("Source file missing", "danger")
        return redirect(url_for("index"))
    # copy into recipient storage
    recipient_dir = user_storage_dir(recipient.username)
    new_unique = f"{uuid.uuid4().hex}.{row['original_name'].rsplit('.',1)[1] if '.' in row['original_name'] else ''}"
    new_path = os.path.join(recipient_dir, new_unique)
    shutil.copy2(src_path, new_path)
    # create thumbnail for images in recipient storage
    try:
        create_thumbnail_if_image(new_path)
    except Exception:
        pass
    size = os.path.getsize(new_path)
    c.execute(
        "INSERT INTO files (owner_id, filename, stored_path, original_name, size, content_type, uploaded_at, original_owner_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            recipient.id,
            new_unique,
            new_path,
            row["original_name"],
            size,
            row["content_type"],
            datetime.utcnow().isoformat(),
            row["owner_id"],
        ),
    )
    new_id = c.lastrowid
    # create thumbnail for images in recipient storage and save path if created
    try:
        thumb_rel = create_thumbnail_if_image(new_path)
        if thumb_rel:
            c.execute("UPDATE files SET thumbnail=? WHERE id=?", (thumb_rel, new_id))
    except Exception:
        pass
    conn.commit()
    conn.close()
    log_activity(current_user.id, "share", f"Shared file {row['original_name']} to {recipient.username}")
    flash(f"Shared with {recipient.username}", "success")
    return redirect(url_for("index"))


@app.route("/organize", methods=["POST"])
@login_required
def organize():
    """Physically organize the current user's uploaded files into category subfolders.
    This moves files on disk into `storage/<username>/<Category>/` and updates DB paths.
    """
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE owner_id=? AND original_owner_id IS NULL", (current_user.id,))
    rows = c.fetchall()
    moved = 0
    for r in rows:
        original_name = r['original_name']
        cat = file_category(original_name)
        user_dir = user_storage_dir(current_user.username)
        cat_dir = os.path.join(user_dir, cat)
        os.makedirs(cat_dir, exist_ok=True)
        src = r['stored_path']
        if not os.path.exists(src):
            continue
        # build a new unique filename within category folder
        ext = original_name.rsplit('.', 1)[1] if '.' in original_name else ''
        new_filename = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
        dest = os.path.join(cat_dir, new_filename)
        try:
            shutil.move(src, dest)
            # move thumbnail stored in user's .thumbs folder if exists and update DB
            abs_src = os.path.abspath(src)
            rel_src = os.path.relpath(abs_src, STORAGE_DIR)
            username = rel_src.split(os.sep)[0]
            src_thumb = os.path.join(STORAGE_DIR, username, '.thumbs', f"thumb_{os.path.basename(src)}.jpg")
            if os.path.exists(src_thumb):
                dest_thumb_dir = os.path.join(STORAGE_DIR, username, '.thumbs')
                os.makedirs(dest_thumb_dir, exist_ok=True)
                dest_thumb = os.path.join(dest_thumb_dir, f"thumb_{os.path.basename(dest)}.jpg")
                shutil.move(src_thumb, dest_thumb)
                # update DB thumbnail path for this file id
                storage_rel = os.path.relpath(dest, STORAGE_DIR).replace('\\', '/')
                thumb_rel = os.path.relpath(dest_thumb, STORAGE_DIR).replace('\\', '/')
                c.execute("UPDATE files SET stored_path=?, filename=?, thumbnail=? WHERE id=?", (dest, os.path.basename(dest), thumb_rel, r['id']))
            else:
                # update only stored_path and filename
                c.execute("UPDATE files SET stored_path=?, filename=? WHERE id=?", (dest, os.path.basename(dest), r['id']))
        except Exception:
            continue
        # update DB stored_path and filename
        c.execute("UPDATE files SET stored_path=?, filename=? WHERE id=?", (dest, new_filename, r['id']))
        moved += 1
    conn.commit()
    conn.close()
    flash(f"Organized {moved} files into category folders", "success")
    return redirect(url_for('index'))


@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file owned by the current user: remove file from disk, remove thumbnail if present, and delete DB row."""
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=?", (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash('File not found', 'danger')
        return redirect(url_for('index'))
    # Only owner can delete their file (this covers shared copies too)
    if row['owner_id'] != current_user.id:
        conn.close()
        flash('Permission denied', 'danger')
        return redirect(url_for('index'))
    stored = row['stored_path']
    # remove file
    try:
        if os.path.exists(stored):
            os.remove(stored)
    except Exception:
        pass
    # remove thumbnail if present in user's .thumbs
    try:
        abs_stored = os.path.abspath(stored)
        rel = os.path.relpath(abs_stored, STORAGE_DIR)
        username = rel.split(os.sep)[0]
        thumb_path = os.path.join(STORAGE_DIR, username, '.thumbs', f"thumb_{os.path.basename(stored)}.jpg")
        if os.path.exists(thumb_path):
            os.remove(thumb_path)
    except Exception:
        pass
    # delete DB record
    c.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    log_activity(current_user.id, 'delete', f"Deleted file {row['original_name']}")
    flash('File deleted', 'info')
    return redirect(url_for('index'))


@app.route("/api/online")
@login_required
def api_online():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE is_online=1 AND id!=?", (current_user.id,))
    rows = c.fetchall()
    conn.close()
    return jsonify([r["username"] for r in rows])


@app.route('/storage/<path:relpath>')
@login_required
def storage_file(relpath):
    """Serve files from the storage directory safely. relpath is a path relative to storage/.
    Authorization: only the owning user may access a stored file or its thumbnail.
    """
    try:
        abs_path = safe_storage_path(relpath)
    except ValueError:
        return "Invalid path", 400
    if not os.path.exists(abs_path):
        return "Not found", 404
    # Try to find a matching DB entry either by stored_path (absolute) or thumbnail (storage-relative)
    rel = os.path.relpath(abs_path, STORAGE_DIR).replace('\\', '/')
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE stored_path=? OR thumbnail=?", (abs_path, rel))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    # only allow the owning user to access the file/thumbnail
    if row['owner_id'] != current_user.id:
        return "Forbidden", 403
    directory = os.path.dirname(abs_path)
    filename = os.path.basename(abs_path)
    return send_from_directory(directory, filename)


@app.route('/activities')
@login_required
def activities():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT a.*, u.username FROM activities a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 200")
    rows = c.fetchall()
    conn.close()
    return render_template('activities.html', activities=rows)


def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)

    return wrapper


@app.route('/admin')
@login_required
@admin_required
def admin():
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT id, username, is_online, is_admin FROM users ORDER BY id')
    rows = c.fetchall()
    users = []
    for r in rows:
        users.append({'id': r['id'], 'username': r['username'], 'is_online': bool(r['is_online']), 'is_admin': bool(r['is_admin']) if 'is_admin' in r.keys() else False})
    conn.close()
    return render_template('admin.html', users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    # Prevent deleting self
    if user_id == current_user.id:
        flash('Cannot delete yourself', 'warning')
        return redirect(url_for('admin'))
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash('User not found', 'danger')
        return redirect(url_for('admin'))
    username = row['username']
    # delete user's files from storage and DB
    c.execute('SELECT id, stored_path FROM files WHERE owner_id=?', (user_id,))
    files = c.fetchall()
    for f in files:
        try:
            if os.path.exists(f['stored_path']):
                os.remove(f['stored_path'])
        except Exception:
            pass
    c.execute('DELETE FROM files WHERE owner_id=?', (user_id,))
    c.execute('DELETE FROM activities WHERE user_id=?', (user_id,))
    c.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'User {username} and their files deleted', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    import secrets

    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id=?', (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash('User not found', 'danger')
        return redirect(url_for('admin'))
    new_pw = secrets.token_urlsafe(8)
    c.execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(new_pw), user_id))
    conn.commit()
    conn.close()
    # show the new password once to the admin via flash (visible on admin page)
    flash(f'New password for {row["username"]}: {new_pw} (shown once)', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/delete_all', methods=['POST'])
@login_required
@admin_required
def admin_delete_all():
    # require explicit confirmation string
    confirm = request.form.get('confirm', '')
    if confirm.strip() != 'DELETE ALL':
        flash("Type 'DELETE ALL' in the confirmation box to perform permanent deletion", 'warning')
        return redirect(url_for('admin'))
    # Delete storage contents (keep storage dir)
    try:
        for entry in os.listdir(STORAGE_DIR):
            p = os.path.join(STORAGE_DIR, entry)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.remove(p)
                except Exception:
                    pass
    except Exception:
        pass
    # wipe DB tables except keep admin users
    conn = db_conn()
    c = conn.cursor()
    c.execute('DELETE FROM files')
    c.execute('DELETE FROM activities')
    # delete non-admin users
    c.execute('DELETE FROM users WHERE is_admin IS NULL OR is_admin=0')
    conn.commit()
    conn.close()
    flash('All non-admin user data has been permanently deleted', 'info')
    return redirect(url_for('admin'))


@app.route("/api/shared")
@login_required
def api_shared():
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "SELECT id, original_name, uploaded_at, original_owner_id FROM files WHERE owner_id=? AND original_owner_id IS NOT NULL ORDER BY uploaded_at DESC",
        (current_user.id,),
    )
    rows = c.fetchall()
    conn.close()
    files = [dict(id=r["id"], original_name=r["original_name"], uploaded_at=r["uploaded_at"], original_owner_id=r["original_owner_id"]) for r in rows]
    return jsonify(files)


if __name__ == "__main__":
    init_db()
    # Run without the reloader/debugger to avoid template parsing conflicts on older Python/Jinja combinations
    app.run(host="0.0.0.0", port=5000, debug=False)
