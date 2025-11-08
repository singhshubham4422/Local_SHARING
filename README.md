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
