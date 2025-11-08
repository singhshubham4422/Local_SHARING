import os
import subprocess
from bs4 import BeautifulSoup
from mdutils.mdutils import MdUtils
import sqlite3
import markdown2

# === CONFIG ===
PROJECT_DIR = os.getcwd()  # dynamically detect current folder
REPORT_FILE = os.path.join(PROJECT_DIR, "PROJECT_DOCUMENTATION.md")
HTML_REPORT_FILE = os.path.splitext(REPORT_FILE)[0] + ".html"
DB_FILE = os.path.join(PROJECT_DIR, "data.db")

md = MdUtils(file_name=REPORT_FILE, title="📘 Local Cloud Drive — Full Project Documentation")

# === 1️⃣ PYTHON / FLASK DOCS ===
md.new_header(level=1, title="🐍 Flask & Python Documentation")

try:
    # Find all Python files in the project root (no need to use PROJECT_DIR as a module)
    py_files = [f for f in os.listdir(PROJECT_DIR) if f.endswith(".py")]

    if not py_files:
        md.new_paragraph("⚠️ No Python files found for documentation.")
    else:
        os.makedirs("docs", exist_ok=True)
        for py_file in py_files:
            try:
                subprocess.run(["pdoc", "--output-dir", "docs", py_file], check=True)
                doc_path = os.path.join("docs", py_file.replace(".py", ".html"))
                md.new_header(level=2, title=py_file)
                md.new_paragraph(f"Generated documentation: `{doc_path}`")
            except subprocess.CalledProcessError as e:
                md.new_paragraph(f"⚠️ pdoc could not process `{py_file}`: {e}")
except Exception as e:
    md.new_paragraph(f"⚠️ Unexpected error generating Python documentation: {e}")

# === 2️⃣ HTML TEMPLATE DOCS ===
md.new_header(level=1, title="🧩 HTML Templates Summary")
templates_dir = os.path.join(PROJECT_DIR, "templates")

if os.path.exists(templates_dir):
    for root, _, files in os.walk(templates_dir):
        for file in files:
            if file.endswith(".html"):
                path = os.path.join(root, file)
                with open(path, encoding="utf-8") as f:
                    soup = BeautifulSoup(f, "html.parser")
                    md.new_header(level=2, title=file)
                    md.new_paragraph(f"Contains **{len(soup.find_all())} HTML tags**.")
                    if soup.title:
                        md.new_paragraph(f"Title: **{soup.title.string}**")
                    if links := soup.find_all("a"):
                        md.new_paragraph(f"Links found: **{len(links)}**")
                    if forms := soup.find_all("form"):
                        md.new_paragraph(f"Forms found: **{len(forms)}**")
else:
    md.new_paragraph("⚠️ No templates directory found.")

# === 3️⃣ DATABASE DOCS ===
if os.path.exists(DB_FILE):
    md.new_header(level=1, title="💾 Database Schema Overview")
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        for (table_name,) in tables:
            md.new_header(level=2, title=table_name)
            schema = cursor.execute(f"PRAGMA table_info({table_name});").fetchall()
            table_text = "Column | Type | Nullable | Default\n---|---|---|---\n"
            for col in schema:
                table_text += f"{col[1]} | {col[2]} | {'No' if col[3] else 'Yes'} | {col[4]}\n"
            md.new_paragraph(table_text)
        conn.close()
    except Exception as e:
        md.new_paragraph(f"⚠️ Error reading database: {e}")
else:
    md.new_paragraph("⚠️ No database file found.")

# === 4️⃣ STATIC FILE SUMMARY ===
static_dir = os.path.join(PROJECT_DIR, "static")
if os.path.exists(static_dir):
    md.new_header(level=1, title="🎨 Static Assets Overview")
    for root, _, files in os.walk(static_dir):
        for file in files:
            ext = os.path.splitext(file)[1]
            relative_path = os.path.relpath(os.path.join(root, file), PROJECT_DIR)
            md.new_paragraph(f"- `{relative_path}` ({ext})")
else:
    md.new_paragraph("⚠️ No static directory found.")

# === 5️⃣ REQUIREMENTS, README & REPORT ===
for f in ["README.md", "requirements.txt", "LOCAL_CLOUD_DRIVE_REPORT.md"]:
    path = os.path.join(PROJECT_DIR, f)
    if os.path.exists(path):
        md.new_header(level=1, title=f"📄 {f}")
        with open(path, encoding="utf-8") as content:
            md.new_paragraph(content.read())

# === SAVE REPORT ===
md.create_md_file()
print(f"✅ Markdown documentation generated at:\n{REPORT_FILE}")

# === 6️⃣ CONVERT TO HTML ===
try:
    with open(REPORT_FILE, encoding="utf-8") as f:
        html = markdown2.markdown(f.read(), extras=["tables", "fenced-code-blocks", "toc", "strike", "task_list"])
    styled_html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Project Documentation</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; line-height: 1.6; background: #fafafa; color: #333; }}
            h1, h2, h3 {{ color: #0059b3; }}
            pre, code {{ background: #f2f2f2; padding: 5px 10px; border-radius: 5px; font-family: Consolas, monospace; }}
            table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background: #e6f0ff; }}
            .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px 40px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <div class="container">
        {html}
        </div>
    </body>
    </html>
    """
    with open(HTML_REPORT_FILE, "w", encoding="utf-8") as out:
        out.write(styled_html)
    print(f"🌐 HTML documentation generated at:\n{HTML_REPORT_FILE}")
except Exception as e:
    print(f"⚠️ Failed to generate HTML version: {e}")
