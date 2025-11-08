
📘 Local Cloud Drive — Full Project Documentation
================================================

# 🐍 Flask & Python Documentation


⚠️ pdoc could not process `app.py`: Command '['pdoc', '--output-dir', 'docs', 'app.py']' returned non-zero exit status 1.

⚠️ pdoc could not process `auto_generate_report.py`: Command '['pdoc', '--output-dir', 'docs', 'auto_generate_report.py']' returned non-zero exit status 1.
# 🧩 HTML Templates Summary

## activities.html


Contains **17 HTML tags**.
## index.html


Contains **64 HTML tags**.

Links found: **2**

Forms found: **5**
## layout.html


Contains **26 HTML tags**.

Title: **Local Cloud Drive**

Links found: **4**
## login.html


Contains **10 HTML tags**.

Links found: **1**

Forms found: **1**
## register.html


Contains **10 HTML tags**.

Links found: **1**

Forms found: **1**
# 💾 Database Schema Overview

## users


Column | Type | Nullable | Default
---|---|---|---
id | INTEGER | Yes | None
username | TEXT | No | None
password_hash | TEXT | No | None
is_online | INTEGER | Yes | 0

## sqlite_sequence


Column | Type | Nullable | Default
---|---|---|---
name |  | Yes | None
seq |  | Yes | None

## files


Column | Type | Nullable | Default
---|---|---|---
id | INTEGER | Yes | None
owner_id | INTEGER | No | None
filename | TEXT | No | None
stored_path | TEXT | No | None
original_name | TEXT | No | None
size | INTEGER | Yes | None
content_type | TEXT | Yes | None
uploaded_at | TEXT | Yes | None
original_owner_id | INTEGER | Yes | None
thumbnail | TEXT | Yes | None

## activities


Column | Type | Nullable | Default
---|---|---|---
id | INTEGER | Yes | None
user_id | INTEGER | Yes | None
verb | TEXT | Yes | None
details | TEXT | Yes | None
created_at | TEXT | Yes | None

# 🎨 Static Assets Overview


- `static/styles.css` (.css)

- `static/icons/archives.svg` (.svg)

- `static/icons/audio.svg` (.svg)

- `static/icons/code.svg` (.svg)

- `static/icons/documents.svg` (.svg)

- `static/icons/images.svg` (.svg)

- `static/icons/other.svg` (.svg)

- `static/icons/videos.svg` (.svg)
# 📄 README.md


Local Cloud Drive
==================

A small Flask-based "mini cloud" that runs entirely offline on your LAN. Each user has a private folder under `storage/`. Files can be uploaded, downloaded, and shared with other users on the same network. Users register and log in with credentials stored in a local SQLite database (passwords are hashed).

Quick start
-----------

1. (Recommended) Create a Python virtualenv and activate it.

2. Install requirements:

   pip install -r requirements.txt

3. Run the app:

   python app.py

Note: start the server with `python app.py`. There is no `main.py` in this project — use `app.py` as shown.

4. From another device on the same Wi-Fi/LAN, open a browser and visit:

   http://<HOST_IP>:5000/

   where <HOST_IP> is the IP address of the machine running the app (e.g. 192.168.1.42).

Notes and features
------------------

- SQLite database file: `data.db` (auto-created on first run).
- Per-user storage: `storage/<username>/` — files are saved with unique names to avoid collisions.
- Sharing: when you share a file, a copy is placed into the recipient's storage and appears in their "Shared With Me" section.
- Online users: tracked by an `is_online` flag set at login/logout; the dashboard lists other online users.
- File limits: basic allowed extensions and a 50 MB upload limit are enforced.

Security
--------

This app is intended for offline LAN use. The following security findings were identified in the current implementation and should be addressed before wider or public deployment. Items are prioritized (High → Medium → Low) with concrete remediation guidance.

High priority
-------------

- Public file serving (/storage/<path>) is unauthenticated and can leak any file under `storage/`.
   - Risk: Confidential files, thumbnails, or uploaded HTML can be retrieved by any LAN user.
   - Remediation: Require authentication on `/storage/*` (add `@login_required`) and enforce DB-backed authorization (only allow owner or explicit shared recipients). Prefer serving previews/images only after validating MIME type; force downloads via `/download/<id>`.

- Unsafe filesystem names for users: usernames are used directly as directory names.
   - Risk: Path traversal or unexpected folders if a username includes path characters or unicode tricks.
   - Remediation: Restrict usernames to a safe whitelist (e.g. `^[A-Za-z0-9_.-]{3,32}$`) or map on-disk folders to user IDs/hashes (for example `storage/users/<user_id>/`).

- Missing CSRF protection on state-changing POST endpoints (upload, share, delete, organize, register, login).
   - Risk: CSRF attacks can trick an authenticated user into performing actions.
   - Remediation: Add CSRF protection (Flask-WTF `CSRFProtect`) and include tokens in all forms. For APIs, use token-based auth or same-site cookies + CSRF.

Medium priority
---------------

- Session and cookie hardening is not configured.
   - Risk: Session theft or fixation in unhealthy deployment contexts.
   - Remediation: Set `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, and `SESSION_COOKIE_SECURE = True` when running over HTTPS. Regenerate/clear session on login (e.g., `session.clear()` before `login_user`). Ensure `SECRET_KEY` is set from the environment and is strong.

- Uploaded files may contain HTML/JS (stored XSS) and are served inline by `/storage/`.
   - Risk: A malicious upload could run script in other users' browsers.
   - Remediation: Validate file types for inline preview (only images). Use Pillow to verify images before creating/serving thumbnails (`Image.verify()`), and force download for non-images with `Content-Disposition: attachment`.

- Thumbnail generation operates synchronously on uploaded files.
   - Risk: Large or malicious images can cause high CPU/memory usage or crash Pillow.
   - Remediation: Verify images, limit image dimensions and pixel counts, or perform thumbnailing in a worker subprocess with stricter time/memory limits.

Low priority / Recommended
-------------------------

- Rate limiting and brute-force protections are absent.
   - Remediation: Add rate limiting (Flask-Limiter), lockouts after repeated failed logins, and consistent error messages to prevent username enumeration.

- DB stores absolute paths (stored_path) which couples data to the host filesystem and may leak paths.
   - Remediation: Store storage-relative paths (eg `username/dir/uuid.ext`) and construct absolute paths at runtime via a single canonical base (`STORAGE_DIR`).

- Organize() file-move logic can perform multiple DB updates and may leave DB inconsistent if moves fail.
   - Remediation: Wrap operations in a DB transaction, perform the file move first and then a single DB update for the record; if move fails, roll back the DB change.

Operational recommendations
-------------------------

- Run behind a reverse proxy (nginx) and enable TLS (HTTPS) for any network beyond a trusted LAN. Set `SESSION_COOKIE_SECURE=True` when TLS is active.
- Restrict filesystem permissions for the `storage/` directory to the service user (least privilege).
- Keep dependencies (Flask, Werkzeug, Pillow) updated and monitor CVE advisories.
- Add an audit/monitoring endpoint that Admins can use to check recent `activities` and suspicious patterns.

Quick prioritized action list (short, practical)
----------------------------------------------
1. Immediately require authentication on `/storage/<path>` and route inline previews through a DB-authorized endpoint (fast; ~10–30 min).
2. Enforce a strict username policy or switch to ID-based storage folders; migrate existing folders carefully (~30–60 min).
3. Add CSRF protection with Flask-WTF and update templates to include tokens (~15–30 min).
4. Restrict inline previews to verified images only and force-download for all other file types (~15–30 min).
5. Set secure cookie flags and ensure `SECRET_KEY` is set via environment (~5–15 min).

Code snippets / hints
---------------------
- Require login for storage route and DB authorization (conceptual):

   @app.route('/storage/<path:relpath>')
   @login_required
   def storage_file(relpath):
         abs_path = safe_storage_path(relpath)
         conn = db_conn()
         c = conn.cursor()
         c.execute('SELECT owner_id, original_owner_id FROM files WHERE stored_path=?', (abs_path,))
         row = c.fetchone()
         if not row or (row['owner_id'] != current_user.id and row['original_owner_id'] != current_user.id):
               return 'Forbidden', 403
         return send_from_directory(os.path.dirname(abs_path), os.path.basename(abs_path))

- Enforce username whitelist at registration:

   import re
   if not re.match(r'^[A-Za-z0-9_.-]{3,32}$', username):
         flash('Invalid username', 'danger')

- Add CSRFProtect (Flask-WTF):

   from flask_wtf import CSRFProtect
   csrf = CSRFProtect(app)

   Then include token in forms (`{{ csrf_token() }}`) or use FlaskForm.

Final note
----------
These changes intentionally increase safety for LAN use and are required before exposing the app beyond a trusted local network. If you want, I can implement the top-priority fixes directly and run a verification test (register/upload/share/delete) and then append the test output to the project report.


Optional enhancements
---------------------

- Use Socket.IO for real-time presence and updates.
- Add user avatars and nicer UI via Bootstrap or TailwindCSS.
- Add admin tools to manage users and storage usage.

License
-------

This example is provided as-is for educational purposes.

# 📄 requirements.txt


Flask==1.1.4
Flask-Login==0.5.0
Werkzeug==1.0.1
Pillow>=8.0
Flask-WTF==0.14.3

# 📄 LOCAL_CLOUD_DRIVE_REPORT.md


# Local Cloud Drive — Status Report

Date: 2025-11-08

Overview
--------
This report summarizes the current state of the Local Cloud Drive project in the workspace `C:\Users\sshub\OneDrive\Desktop\ChangeEdition_Logs`.

Key artifacts inspected
-----------------------
- `templates/index.html` — current dashboard template
- `app.py` — main Flask app and routes
- `test_client.py` — automated E2E test (attempted to read; not present in workspace)

What I found (high level)
-------------------------
1. Application core
   - `app.py` defines a Flask application with routes for register/login/logout, upload, download, share, organize, delete, storage serving, and API endpoints.
   - SQLite database at `data.db` with tables `users`, `files`, and `activities`. A migration in `init_db()` ensures a `thumbnail` column exists in `files`.
   - Authentication handled with `flask_login`. Passwords are hashed using Werkzeug.

2. File storage and thumbnails
   - Per-user storage under `storage/<username>/`.
   - Thumbnail creation implemented in `create_thumbnail_if_image()` using Pillow; thumbnails stored at `storage/<username>/.thumbs/thumb_<stored_filename>.jpg`. DB `files.thumbnail` stores a storage-relative path when available.
   - `storage_file` route safely serves files from `storage/` after path normalization.

3. Upload / Share / Organize / Delete
   - Uploads save files with a UUID filename into the user's storage folder, then insert a `files` DB row. Thumbnails are created if the file is an image.
   - Share copies a file into the recipient's storage and inserts a `files` row for the recipient with `original_owner_id` set.
   - Organize moves files on disk into category subfolders (`Documents`, `Images`, etc.) and updates DB paths; attempts to move thumbnails too.
   - Delete removes file and thumbnail (if present) and deletes DB record; owner-only access enforced.

4. UI (dashboard)
   - `templates/index.html` is the dashboard template. It includes a simple upload form (no drag/drop), grouped "My Files" by category, "Shared With Me" and an "Online Users" list.
   - File rows include thumbnail logic (use `f.thumbnail` when present; fallback to category icons). Share and Delete forms are present per file.

5. Automated test
   - A `test_client.py` was created previously but is not present/readable in the current workspace (not found at expected path). Because it's missing, I couldn't run the E2E test automatically at this time.

Findings from inspected files
----------------------------
- From `templates/index.html`:
  - Upload form posts to `url_for('upload')` with `enctype="multipart/form-data"`.
  - Files are grouped and rendered with `f['storage_rel']` and `f['thumbnail']` fields; share uses a small inline form asking for recipient username.
  - Category icons are expected at `/static/icons/<category>.svg`.

- From `app.py`:
  - `MAX_CONTENT_LENGTH` is 50 MB; `ALLOWED_EXTENSIONS` variable exists but `allowed_file()` now allows any non-dot-starting filename.
  - `init_db()` runs on app start and attempts to add `thumbnail` column if missing.
  - The server is started with `app.run(host='0.0.0.0', port=5000, debug=False)`.

Missing or unexpected items
--------------------------
- `test_client.py` could not be read from the workspace path. If you have a local copy elsewhere, please point me to it or I can recreate it (I previously created a small `test_client.py` for automated tests).
- `data.db` was not inspected in this run (I did not open the DB file). If you want DB inspection included, I can open it and list rows after a test run.

How to run the app and the test (PowerShell)
--------------------------------------------
1) Ensure dependencies are installed (in the Python environment you use):

```powershell
pip install -r requirements.txt
pip install requests  # needed for the test client
```

2) Start the Flask app (run from the project root):

```powershell
python .\app.py
```

3) In a new PowerShell window run the test (if `test_client.py` is present):

```powershell
python .\test_client.py
```

If the test script is missing, I can recreate it for you.

Recommended next steps
----------------------
- Option A — Run the automated E2E test now:
  - I can start the app and run the test client, capture results, inspect `data.db` and `storage/` to confirm the flows (register, upload, share, delete). Tell me to proceed and whether you want the server started by me or you will start it first.

- Option B — Recreate the missing `test_client.py` in the workspace and run locally yourself:
  - If you prefer to run locally, I can re-add the test script and provide exact PowerShell commands.

- Small improvements to add (low-risk, high-value):
  - Add an admin utility script to dump DB rows for quick verification.
  - When organizing, avoid double-updating DB rows (the current `organize()` updates stored_path/filename multiple times); I can tighten that logic.
  - Add a small unit test harness that uses Flask's test client to avoid starting the full server for quick checks.

Artifacts created/modified by this operation
-------------------------------------------
- `LOCAL_CLOUD_DRIVE_REPORT.md` — this report (created in project root).
- Todo list updated: `Gather key files` marked completed; `Write report file` marked in-progress.

What I can do next (pick one)
-----------------------------
1. Start the Flask app and run an automated E2E test now, capture logs + DB snapshot, and append test results to this report.
2. Recreate `test_client.py` (if you want it in the repo) and run it here.
3. Run DB inspection only (show `users` and `files` rows) if the server is down and you prefer not to start it.

Tell me which option you prefer and whether I should start the server or you will. If you want the E2E run, confirm and I'll proceed immediately and append test results to this report.

-- End of report
