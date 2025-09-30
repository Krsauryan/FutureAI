"""
Flask example implementing the Website Authorization Workflow for a PUBLIC SP-API application.

Notes:
- This is an example for educational/testing purposes. Do NOT use in production without
  adding proper persistence, encryption, rate limiting, logging, and error handling.
- Register these URIs with Amazon Seller Central when you create the application.
- Set REFERRER-POLICY header (no-referrer) as required by Amazon documentation.

How it works (overview):
1. /           -> Landing page with "Authorize" button that redirects the seller to Seller Central consent.
2. /login      -> Log-in URI: Amazon will call this with amazon_callback_uri, amazon_state, selling_partner_id.
                 We use this to associate the incoming auth with a local user/session and then redirect
                 the seller to amazon_callback_uri with our generated `state` (and amazon_state).
3. /sp-api/auth -> Redirect URI: Amazon will call this after the seller granted permissions with
                 parameters: state, selling_partner_id, spapi_oauth_code. We validate state, then exchange
                 spapi_oauth_code for refresh token (LWA) and store it.
4. /token      -> Runtime example: exchange refresh_token for an access_token (grant_type=refresh_token)

Configure environment variables below or modify code to use a .env loader in real usage.
"""

from flask import Flask, request, redirect, session, url_for, render_template_string, jsonify, make_response
import secrets
import time
import requests
import urllib.parse
import os
from dotenv import load_dotenv
load_dotenv()
# ========= Configuration (replace these with environment variables in production) =========


CLIENT_ID = os.getenv("LWA_CLIENT_ID", "your_lwa_client_id")
CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET", "your_lwa_client_secret")
APPLICATION_ID = os.getenv("AMZN_APPLICATION_ID", "amzn1.sp.solution.01ca13ef-3ff6-4752-8b09-cb42659ea775")
# The redirect URI you register with Amazon for OAuth responses
REGISTERED_REDIRECT_URI = os.getenv("REGISTERED_REDIRECT_URI", "https://eluraindia.com/pages/about-us/sp-api/auth")
# The log-in URI you register with Amazon (this app's /login)
# region-specific sellercentral base for constructing authorization URIs. Add others if needed.
SELLER_CENTRAL_BASE = os.getenv("SELLER_CENTRAL_BASE", "https://sellercentral.amazon.in")
# LWA token endpoint
LWA_TOKEN_URL = "https://api.amazon.com/auth/o2/token"

# ======================================================================================


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# IMPORTANT: production must use persistent storage and encryption for these objects.
# For demo purposes we store states and tokens in-memory. This will be lost on restart and
# is NOT secure for real applications.
INCOMING_AMAZON_STATE_STORE = {}   # key: amazon_state -> data about the incoming login request
OUTBOUND_STATE_STORE = {}          # key: our_state -> {selling_partner_id, timestamp, amazon_state}
REFRESH_TOKEN_STORE = {}           # key: selling_partner_id -> refresh_token (encrypt in prod)

# Basic HTML templates (kept inline for example)
INDEX_HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>SP-API Website Authorization Example</title>
  </head>
  <body>
    <h1>Authorize Example App</h1>
    <p>Click the button to start authorization.</p>
    <form method="get" action="{{ authorize_url }}">
      <button type="submit">Authorize with Seller Central</button>
    </form>
    <hr>
    <p>Test endpoints:</p>
    <ul>
      <li><a href="/login">/login (log-in URI)</a> - typically called by Amazon</li>
      <li><a href="/sp-api/auth">/sp-api/auth (redirect URI)</a> - will be called by Amazon after consent</li>
    </ul>
  </body>
</html>
"""

# Ensure Amazon-required header to prevent CSRF via referrer
@app.after_request
def set_security_headers(response):
    # As per Amazon docs: Referrer-Policy: no-referrer
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def generate_state():
    """Generate a short-lived, hard-to-guess state token."""
    return secrets.token_urlsafe(24)


def build_authorization_uri(region_base=None, version_beta=False, state=None):
    """Construct the authorization URI that sends a seller to the Seller Central consent page."""
    base = SELLER_CENTRAL_BASE
    path = "/apps/authorize/consent"
    params = {
        'application_id': APPLICATION_ID,
        'state': state or generate_state()
    }
    if version_beta:
        params['version'] = 'beta'
    return f"{base}{path}?{urllib.parse.urlencode(params)}"


@app.route('/')
def index():
    # Build a fresh state for this button click; store it so we can validate later.
    our_state = generate_state()
    OUTBOUND_STATE_STORE[our_state] = {
        'timestamp': time.time(),
        'note': 'state created from landing page button'
    }
    authorize_url = build_authorization_uri(state=our_state, version_beta=False)
    return render_template_string(INDEX_HTML, authorize_url=authorize_url)


@app.route('/login')
def login_endpoint():
    """
    Example Log-in URI endpoint. Amazon will redirect sellers here (the URI you registered as Log-in URI)
    with query parameters: amazon_callback_uri, amazon_state, selling_partner_id, and (optionally) version=beta.

    This endpoint should:
    - Authenticate the seller if necessary (session or account mapping).
    - Store the amazon_state and selling_partner_id and then redirect the user to amazon_callback_uri
      including parameters: redirect_uri (optional), amazon_state, and our state token.

    In this sample, we accept the incoming params and respond by redirecting to amazon_callback_uri.
    """
    amazon_callback_uri = request.args.get('amazon_callback_uri')
    amazon_state = request.args.get('amazon_state')
    selling_partner_id = request.args.get('selling_partner_id')
    version = request.args.get('version')

    # Basic parameter validation
    if not amazon_callback_uri or not amazon_state or not selling_partner_id:
        return "Missing required parameters in login uri", 400

    # In a real app: authenticate the user or map selling_partner_id <-> local account.
    # Here we simply store the incoming amazon_state so the flow can proceed.
    INCOMING_AMAZON_STATE_STORE[amazon_state] = {
        'selling_partner_id': selling_partner_id,
        'timestamp': time.time(),
        'version': version
    }

    # Generate our state token to protect the redirect round-trip
    our_state = generate_state()
    OUTBOUND_STATE_STORE[our_state] = {
        'selling_partner_id': selling_partner_id,
        'timestamp': time.time(),
        'amazon_state': amazon_state
    }

    # Build parameters to send back to amazon_callback_uri per docs
    callback_params = {
        'amazon_state': amazon_state,
        'state': our_state
    }
    # If you want Amazon to use a specific redirect URI (must be registered), include redirect_uri in params.
    # callback_params['redirect_uri'] = REGISTERED_REDIRECT_URI
    if version == 'beta':
        callback_params['version'] = 'beta'

    redirect_location = f"{amazon_callback_uri}?{urllib.parse.urlencode(callback_params)}"
    response = redirect(redirect_location)
    return response


@app.route('/sp-api/auth')
def redirect_uri_handler():
    """
    This is the Redirect URI (REGISTERED_REDIRECT_URI). Amazon will call this after the seller grants permission.
    Expected query params: state, selling_partner_id, spapi_oauth_code
    """
    state = request.args.get('state')
    selling_partner_id = request.args.get('selling_partner_id')
    spapi_oauth_code = request.args.get('spapi_oauth_code')

    if not state or not selling_partner_id or not spapi_oauth_code:
        return "Missing required parameters in sp-api/auth", 400

    # Validate state - ensure it exists in our outbound state store
    stored = OUTBOUND_STATE_STORE.get(state)
    if not stored:
        return "Invalid or expired state", 400

    # Optional: confirm selling_partner_id matches the stored value (if you stored it there)
    if stored.get('selling_partner_id') and stored.get('selling_partner_id') != selling_partner_id:
        return "Mismatched selling_partner_id", 400

    # Exchange spapi_oauth_code for tokens with LWA
    token_response = exchange_authorization_code_for_tokens(spapi_oauth_code, REGISTERED_REDIRECT_URI)
    if not token_response or 'refresh_token' not in token_response:
        return "Failed to exchange authorization code for tokens", 500

    # Store refresh token securely — here we store in memory for demo purposes
    refresh_token = token_response['refresh_token']
    REFRESH_TOKEN_STORE[selling_partner_id] = {
        'refresh_token': refresh_token,
        'received_at': time.time()
    }

    # Clean up state stores (optional)
    try:
        del OUTBOUND_STATE_STORE[state]
    except KeyError:
        pass

    # Confirm success to the user
    html = f"Authorization successful for selling_partner_id: {selling_partner_id}. Refresh token stored (demo)."
    return html


def exchange_authorization_code_for_tokens(spapi_oauth_code, redirect_uri):
    """Call LWA to exchange authorization code for access & refresh tokens."""
    payload = {
        'grant_type': 'authorization_code',
        'code': spapi_oauth_code,
        'redirect_uri': redirect_uri,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }
    try:
        resp = requests.post(LWA_TOKEN_URL, data=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        app.logger.exception('Failed to call LWA token endpoint')
        return None


@app.route('/token', methods=['POST'])
def runtime_token_exchange():
    """
    Example endpoint: exchange a stored refresh token for a runtime access token.
    POST JSON: { "selling_partner_id": "..." }
    Returns: access_token JSON from LWA.
    """
    data = request.get_json() or {}
    selling_partner_id = data.get('selling_partner_id')
    if not selling_partner_id:
        return jsonify({'error': 'selling_partner_id required'}), 400

    entry = REFRESH_TOKEN_STORE.get(selling_partner_id)
    if not entry:
        return jsonify({'error': 'no refresh token for seller'}), 404

    refresh_token = entry['refresh_token']
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
    try:
        resp = requests.post(LWA_TOKEN_URL, data=payload, headers=headers)
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.RequestException:
        app.logger.exception('Failed to exchange refresh token')
        return jsonify({'error': 'token exchange failed'}), 500


if __name__ == '__main__':
    # Run with debug=False in real deployments and behind a proper WSGI server
    app.run(host='0.0.0.0', port=8000, debug=True)
