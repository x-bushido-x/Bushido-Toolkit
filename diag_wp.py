"""
Diagnostic: test WordPress login step by step using requests library.
Run: python diag_wp.py
"""
import requests
import re
import urllib3
urllib3.disable_warnings()

HOST = 'listinghive.hivepress.io'
URL  = f'https://{HOST}/wp-login.php'

# Test with the known-good credentials
TEST_USER = 'demo'
TEST_PASS = 'demo123!!'   # adjust if needed

session = requests.Session()
session.verify = False
session.headers.update({
    'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                   'AppleWebKit/537.36 (KHTML, like Gecko) '
                   'Chrome/120.0.0.0 Safari/537.36'),
    'Accept': 'text/html,application/xhtml+xml,*/*',
    'Accept-Language': 'en-US,en;q=0.9',
})

print("=" * 60)
print(f"STEP 1: GET {URL}")
print("=" * 60)

r1 = session.get(URL, allow_redirects=True, timeout=10)
print(f"Status      : {r1.status_code}")
print(f"Final URL   : {r1.url}")
print(f"Cookies     : {dict(session.cookies)}")

nonce_m = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r1.text)
nonce = nonce_m.group(1) if nonce_m else ''
print(f"Nonce       : {repr(nonce)}")
print(f"Body (300c) : {r1.text[:300]}")

print()
print("=" * 60)
print(f"STEP 2: POST {TEST_USER} / {TEST_PASS}")
print("=" * 60)

post_data = {
    'log':         TEST_USER,
    'pwd':         TEST_PASS,
    'wp-submit':   'Log In',
    'redirect_to': '/wp-admin/',
    'testcookie':  '1',
}
if nonce:
    post_data['_wpnonce'] = nonce

session.cookies.set('wordpress_test_cookie', 'WP Cookie check', domain=HOST)

r2 = session.post(URL, data=post_data, allow_redirects=False, timeout=10,
                  headers={'Referer': URL, 'Origin': f'https://{HOST}'})

print(f"Status      : {r2.status_code}")
print(f"Location    : {r2.headers.get('Location', 'NONE')}")
print(f"Set-Cookie  : {r2.headers.get('Set-Cookie', 'NONE')[:200]}")
print(f"All r2 cookies : {dict(r2.cookies)}")
print(f"Session cookies: {dict(session.cookies)}")
print(f"Body (300c) : {r2.text[:300]}")

loc = r2.headers.get('Location', '').lower()
all_cookie_names = list(r2.cookies.keys()) + list(session.cookies.keys())
has_logged_in = any('wordpress_logged_in_' in c for c in all_cookie_names)
if 'wordpress_logged_in_' in r2.headers.get('Set-Cookie', ''):
    has_logged_in = True

print()
print("SUCCESS CHECK:")
print(f"  302?                   : {r2.status_code == 302}")
print(f"  wp-admin in location?  : {'wp-admin' in loc}")
print(f"  wp-login NOT in loc?   : {'wp-login' not in loc}")
print(f"  logged_in cookie?      : {has_logged_in}")
print(f"  RESULT: {'SUCCESS' if (r2.status_code == 302 and 'wp-admin' in loc and has_logged_in) else 'FAIL'}")
