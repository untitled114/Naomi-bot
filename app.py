from flask import Flask, request, redirect, url_for, session, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from requests_oauthlib import OAuth2Session
import requests
import os
import logging
from datetime import datetime
from config import Config
from sqlalchemy import text
import hashlib
import base64
import secrets

def generate_code_challenge():
    """Generate PKCE code verifier and challenge"""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge

# Configure logging for Azure
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # This ensures logs go to Azure's log stream
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

print(app.config['SQLALCHEMY_DATABASE_URI'])


# Azure-specific session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Force HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',  # Important for OAuth redirects
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)

# Initialize database
db = SQLAlchemy(app)

# Twitter OAuth2 settings
TWITTER_AUTHORIZATION_BASE_URL = 'https://twitter.com/i/oauth2/authorize'
TWITTER_TOKEN_URL = 'https://api.twitter.com/2/oauth2/token'

class TwitterAuth(db.Model):
    """Store Twitter authentication tokens"""
    __tablename__ = 'twitter_auth'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    access_token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TweetInteraction(db.Model):
    """Store tweet interactions for analytics"""
    __tablename__ = 'tweet_interactions'
    
    id = db.Column(db.Integer, primary_key=True)
    tweet_id = db.Column(db.String(50), nullable=False)
    interaction_type = db.Column(db.String(20), nullable=False)  # 'post', 'reply', 'mention'
    content = db.Column(db.Text, nullable=True)
    sentiment_score = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_mentioned = db.Column(db.String(50), nullable=True)
    conversation_id = db.Column(db.String(50), nullable=True)

@app.route('/')
def index():
    """Homepage with OAuth login"""
    if 'oauth_token' in session:
        return render_template('success.html', username=session.get('username', 'Naomi'))
    return render_template('index.html')

@app.route('/login')
def login():
    """Initiate Twitter OAuth flow"""
    try:
        # Generate proper PKCE challenge
        code_verifier, code_challenge = generate_code_challenge()
        
        # Create OAuth2 session
        twitter = OAuth2Session(
            app.config['TWITTER_CLIENT_ID'],
            redirect_uri=app.config['TWITTER_REDIRECT_URI'],
            scope=['tweet.read', 'tweet.write', 'users.read', 'offline.access']
        )
        
        # Get authorization URL with proper PKCE
        authorization_url, state = twitter.authorization_url(
            TWITTER_AUTHORIZATION_BASE_URL,
            code_challenge=code_challenge,
            code_challenge_method='S256'  # Changed from 'plain'
        )
        
        # Store both state and code_verifier in session
        session['oauth_state'] = state
        session['code_verifier'] = code_verifier  # Store verifier, not challenge
        
        logger.info(f"Generated code_verifier: {code_verifier[:10]}...")
        logger.info(f"Redirecting to Twitter OAuth: {authorization_url}")
        return redirect(authorization_url)
        
    except Exception as e:
        logger.error(f"OAuth initiation error: {str(e)}")
        return jsonify({'error': f'Failed to initiate OAuth flow: {str(e)}'}), 500

@app.route('/callback')
def callback():
    """Handle OAuth callback from Twitter"""
    try:
        # Log all incoming request details
        logger.info(f"=== OAuth Callback Received ===")
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request URL: {request.url}")
        logger.info(f"Request args: {dict(request.args)}")
        logger.info(f"Request headers: {dict(request.headers)}")
        logger.info(f"Session data: {dict(session)}")
        
        # Check for error in callback
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'No description')
            logger.error(f"OAuth error: {error} - {error_description}")
            return jsonify({
                'error': f'OAuth error: {error}',
                'description': error_description
            }), 400
        
        # Get authorization code from callback
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code:
            logger.error("No authorization code received in callback")
            return jsonify({'error': 'Authorization code not received'}), 400
            
        logger.info(f"Authorization code received: {code[:10]}...")
            
        # Verify state parameter
        stored_state = session.get('oauth_state')
        if not stored_state:
            logger.error("No stored state found in session")
            return jsonify({'error': 'No stored state found'}), 400
            
        if state != stored_state:
            logger.error(f"State mismatch: received '{state}', expected '{stored_state}'")
            return jsonify({'error': 'Invalid state parameter'}), 400
        
        logger.info("State verification passed")
        
        # Get stored code verifier
        code_verifier = session.get('code_verifier')
        if not code_verifier:
            logger.error("Code verifier not found in session")
            return jsonify({'error': 'Code verifier not found'}), 400
            
        logger.info(f"Using code_verifier: {code_verifier[:10]}...")
        
        # Prepare token exchange data
        token_data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': app.config['TWITTER_CLIENT_ID'],
            'redirect_uri': app.config['TWITTER_REDIRECT_URI'],
            'code_verifier': code_verifier  # Fixed: was using 'code_challenge'
        }
        
        logger.info(f"Token request data: {dict(token_data)}")
        logger.info(f"Making token request to: {TWITTER_TOKEN_URL}")
        
        # Make token request with detailed logging
        token_response = requests.post(
            TWITTER_TOKEN_URL,
            data=token_data,
            auth=(app.config['TWITTER_CLIENT_ID'], app.config['TWITTER_CLIENT_SECRET']),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30  # Add timeout
        )
        
        logger.info(f"Token response status: {token_response.status_code}")
        logger.info(f"Token response headers: {dict(token_response.headers)}")
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            try:
                error_json = token_response.json()
                logger.error(f"Token error JSON: {error_json}")
            except:
                pass
            return jsonify({
                'error': 'Failed to obtain access token',
                'status_code': token_response.status_code,
                'response': token_response.text
            }), 400
            
        token_info = token_response.json()
        logger.info("Token exchange successful!")
        logger.info(f"Token info keys: {list(token_info.keys())}")
        
        # Get user information
        user_response = requests.get(
            'https://api.twitter.com/2/users/me',
            headers={'Authorization': f"Bearer {token_info['access_token']}"}
        )
        
        if user_response.status_code == 200:
            user_data = user_response.json()['data']
            logger.info(f"User data retrieved: {user_data['username']}")
            
            # Store auth info in database
            auth_record = TwitterAuth.query.filter_by(user_id=user_data['id']).first()
            if not auth_record:
                auth_record = TwitterAuth(
                    user_id=user_data['id'],
                    username=user_data['username'],
                    access_token=token_info['access_token'],
                    refresh_token=token_info.get('refresh_token')
                )
                db.session.add(auth_record)
                logger.info("Created new auth record")
            else:
                auth_record.access_token = token_info['access_token']
                auth_record.refresh_token = token_info.get('refresh_token')
                auth_record.updated_at = datetime.utcnow()
                logger.info("Updated existing auth record")
            
            db.session.commit()
            
            # Store in session
            session['oauth_token'] = token_info['access_token']
            session['username'] = user_data['username']
            session['user_id'] = user_data['id']
            
            # Clear OAuth-specific session data
            session.pop('oauth_state', None)
            session.pop('code_verifier', None)
            
            logger.info(f"OAuth flow completed successfully for: {user_data['username']}")
            return redirect(url_for('index'))
        else:
            logger.error(f"Failed to get user info: {user_response.status_code} - {user_response.text}")
            return jsonify({
                'error': 'Failed to get user information',
                'status_code': user_response.status_code,
                'response': user_response.text
            }), 400
            
    except requests.exceptions.Timeout:
        logger.error("Timeout occurred during OAuth callback")
        return jsonify({'error': 'Request timeout'}), 500
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error during OAuth callback: {str(e)}")
        return jsonify({'error': f'Request error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in OAuth callback: {str(e)}")
        logger.exception("Full traceback:")
        return jsonify({'error': f'OAuth callback failed: {str(e)}'}), 500

@app.route('/logout')
def logout():
    """Clear session and logout"""
    session.clear()
    return redirect(url_for('index'))

@app.route('/health')
def health_check():
    """Health check endpoint for Azure"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/bot/status')
def bot_status():
    """Bot status endpoint"""
    return jsonify({
        'bot_name': 'Naomi',
        'status': 'active',
        'personality': 'Data-loving Gen Z with old English charm',
        'last_tweet': None,  # Will be implemented when bot is active
        'interactions_today': 0  # Will be calculated from database
    })

@app.route('/test-callback')
def test_callback():
    """Test route to verify callback URL is working"""
    return jsonify({
        'message': 'Callback URL is accessible',
        'timestamp': datetime.utcnow().isoformat(),
        'host': request.host,
        'url': request.url,
        'headers': dict(request.headers)
    })

@app.route('/debug/env')
def debug_env():
    """Debug endpoint - REMOVE IN PRODUCTION!"""
    env_vars = {
        'TWITTER_CLIENT_ID': app.config.get('TWITTER_CLIENT_ID', 'NOT SET')[:10] + '...' if app.config.get('TWITTER_CLIENT_ID') else 'NOT SET',
        'TWITTER_CLIENT_SECRET': 'SET' if app.config.get('TWITTER_CLIENT_SECRET') else 'NOT SET',
        'TWITTER_REDIRECT_URI': app.config.get('TWITTER_REDIRECT_URI', 'NOT SET'),
        'DATABASE_URL': 'SET' if app.config.get('DATABASE_URL') else 'NOT SET',
        'FLASK_SECRET_KEY': 'SET' if app.config.get('SECRET_KEY') else 'NOT SET',
        'PORT': os.environ.get('PORT', '5000'),
        'WEBSITE_HOSTNAME': os.environ.get('WEBSITE_HOSTNAME', 'NOT SET'),
    }
    return jsonify(env_vars)

if __name__ == '__main__':
    # Create database tables at startup
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
    
    # Run the app
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)