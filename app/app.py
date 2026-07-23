import os
import re
import time
from datetime import datetime, timedelta, timezone

import psycopg2
from flask import Flask, render_template, request

app = Flask(__name__)

# --- OWASP Top 10 2024 Proactive Control C3: Validate All Inputs ---
# Positive (allowlist) validation: only letters, digits and spaces are
# accepted. This also blocks SQL injection / XSS payloads, since those
# require characters (', ", ;, <, >, --, /* etc.) outside the allowlist.
# No unicode handling is required per the assignment scope.
MIN_LENGTH = 3
MAX_LENGTH = 50
ALLOWED_PATTERN = re.compile(r"^[A-Za-z0-9 ]+$")

SGT = timezone(timedelta(hours=8))  # Singapore Time, fixed UTC+8 offset (no DST)

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "db"),
    "dbname": os.environ.get("DB_NAME", "ssddb"),
    "user": os.environ.get("DB_USER", "ssduser"),
    # No hardcoded default: the password must always come from the
    # environment (set in docker-compose.yml), never from source code.
    "password": os.environ.get("DB_PASSWORD"),
}


def is_valid_search_term(term):
    """Backend validation (mirrors the frontend check; never trust the client)."""
    if term is None:
        return False
    if not (MIN_LENGTH <= len(term) <= MAX_LENGTH):
        return False
    return bool(ALLOWED_PATTERN.match(term))


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def init_db():
    """Wait for Postgres to be ready, then ensure the log table exists."""
    for _ in range(15):
        try:
            conn = get_connection()
            break
        except psycopg2.OperationalError:
            time.sleep(2)
    else:
        raise RuntimeError("Could not connect to the database")
    with conn, conn.cursor() as cur:
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS "2401221" (
                id SERIAL PRIMARY KEY,
                search_query VARCHAR(50) NOT NULL,
                query_time TIMESTAMP NOT NULL
            )'''
        )
    conn.close()


def log_search(term):
    # Parameterized query: defense-in-depth against SQL injection
    # (OWASP SQL Injection Prevention Cheat Sheet), on top of input validation.
    conn = get_connection()
    with conn, conn.cursor() as cur:
        cur.execute(
            'INSERT INTO "2401221" (search_query, query_time) VALUES (%s, %s)',
            (term, datetime.now(SGT).replace(tzinfo=None)),
        )
    conn.close()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/search", methods=["POST"])
def search():
    term = request.form.get("search_term", "")
    if not is_valid_search_term(term):
        # Invalid / suspected attack: clear input, stay on home page.
        return render_template("home.html", error="Invalid input. Please try again.")
    log_search(term)
    # {{ term }} is auto-escaped by Jinja2, preventing reflected XSS on output.
    return render_template("result.html", term=term)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
