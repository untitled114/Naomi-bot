from flask import Flask, request, redirect, url_for, session, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from requests_oauthlib import OAuth2Session
import requests
import os
import logging
from datetime import datetime
from config import Config
from sqlalchemy import text

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        # Create OAuth2 session
        twitter = OAuth2Session(
            app.config['TWITTER_CLIENT_ID'],
            redirect_uri=app.config['TWITTER_REDIRECT_URI'],
            scope=['tweet.read', 'tweet.write', 'users.read', 'offline.access']
        )
        
        # Get authorization URL
        authorization_url, state = twitter.authorization_url(
            TWITTER_AUTHORIZATION_BASE_URL,
            code_challenge='challenge',
            code_challenge_method='plain'
        )
        
        # Store state in session for security
        session['oauth_state'] = state
        session['code_challenge'] = 'challenge'
        
        logger.info(f"Redirecting to Twitter OAuth: {authorization_url}")
        return redirect(authorization_url)
        
    except Exception as e:
        logger.error(f"OAuth initiation error: {str(e)}")
        return jsonify({'error': 'Failed to initiate OAuth flow'}), 500

@app.route('/callback')
def callback():
    """Handle OAuth callback from Twitter"""
    try:
        # Get authorization code from callback
        code = request.args.get('code')
        state = request.args.get('state')
        
        if not code:
            return jsonify({'error': 'Authorization code not received'}), 400
            
        # Verify state parameter
        if state != session.get('oauth_state'):
            return jsonify({'error': 'Invalid state parameter'}), 400
        
        # Exchange code for access token
        token_data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': app.config['TWITTER_CLIENT_ID'],
            'redirect_uri': app.config['TWITTER_REDIRECT_URI'],
            'code_verifier': session.get('code_challenge', 'challenge')
        }
        
        # Make token request
        token_response = requests.post(
            TWITTER_TOKEN_URL,
            data=token_data,
            auth=(app.config['TWITTER_CLIENT_ID'], app.config['TWITTER_CLIENT_SECRET']),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            return jsonify({'error': 'Failed to obtain access token'}), 400
            
        token_info = token_response.json()
        
        # Get user information
        user_response = requests.get(
            'https://api.twitter.com/2/users/me',
            headers={'Authorization': f"Bearer {token_info['access_token']}"}
        )
        
        if user_response.status_code == 200:
            user_data = user_response.json()['data']
            
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
            else:
                auth_record.access_token = token_info['access_token']
                auth_record.refresh_token = token_info.get('refresh_token')
                auth_record.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            # Store in session
            session['oauth_token'] = token_info['access_token']
            session['username'] = user_data['username']
            session['user_id'] = user_data['id']
            
            logger.info(f"OAuth successful for user: {user_data['username']}")
            return redirect(url_for('index'))
        else:
            logger.error(f"Failed to get user info: {user_response.text}")
            return jsonify({'error': 'Failed to get user information'}), 400
            
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return jsonify({'error': 'OAuth callback failed'}), 500

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

# Initialize database tables
@app.before_first_request
def create_tables():
    """Create database tables on first request"""
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")

if __name__ == '__main__':
    # Run the app
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)