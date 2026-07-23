"""HTTP-level integration/UI tests against a running instance of the app.

Run with the app + db already up (e.g. `docker compose up -d db app`):
    python tests/test_http.py
"""
import sys

import requests

BASE = "http://localhost"
failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name)
    if not cond:
        failures.append(name)


# Home page structure: one input field, one submit button
r = requests.get(f"{BASE}/")
check("home page loads (200)", r.status_code == 200)
check("home page has exactly one <input>", r.text.count("<input") == 1)
check("home page has a submit button", 'type="submit"' in r.text)

# Length boundary checks (MIN_LENGTH=3, MAX_LENGTH=50)
below_min = requests.post(f"{BASE}/search", data={"search_term": "ab"})
at_min = requests.post(f"{BASE}/search", data={"search_term": "abc"})
at_max = requests.post(f"{BASE}/search", data={"search_term": "x" * 50})
above_max = requests.post(f"{BASE}/search", data={"search_term": "x" * 51})
check("below-minimum length rejected", "Invalid input" in below_min.text)
check("at-minimum length accepted", "Invalid input" not in at_min.text)
check("at-maximum length accepted", "Invalid input" not in at_max.text)
check("above-maximum length rejected", "Invalid input" in above_max.text)

# SQLi / XSS payloads: rejected, input cleared, stays on home page
attack_payloads = [
    "' OR 1=1 --",
    "1; DROP TABLE users",
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    "admin'--",
]
all_blocked = all(
    "Invalid input" in requests.post(f"{BASE}/search", data={"search_term": p}).text
    for p in attack_payloads
)
check("all SQLi/XSS payloads blocked, stay on home page", all_blocked)

# Valid term: distinct result page showing the term, with a way back home
r = requests.post(f"{BASE}/search", data={"search_term": "hello world"})
check("valid term produces 200", r.status_code == 200)
check("valid term is displayed on result page", "hello world" in r.text)
check("result page has no search form", "<input" not in r.text)
check("result page has a way back to home", 'action="/"' in r.text and "Back to Home" in r.text)

print()
if failures:
    print(f"{len(failures)} CHECK(S) FAILED:", failures)
    sys.exit(1)
print("ALL HTTP INTEGRATION CHECKS PASSED")
