import os
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Twitter API Credentials (from Azure App Service settings)
    TWITTER_API_KEY = os.environ.get('TWITTER_API_KEY')
    TWITTER_API_SECRET = os.environ.get('TWITTER_API_SECRET')
    TWITTER_CLIENT_ID = os.environ.get('TWITTER_CLIENT_ID')
    TWITTER_CLIENT_SECRET = os.environ.get('TWITTER_CLIENT_SECRET')
    TWITTER_BEARER_TOKEN = os.environ.get('TWITTER_BEARER_TOKEN')
    
    # OAuth Configuration
    TWITTER_REDIRECT_URI = os.environ.get('TWITTER_REDIRECT_URI') or 'https://naomi-ahfxhmbpgraggqd6.eastus2-01.azurewebsites.net/callback'
    
    # PostgreSQL Database Configuration
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or 'postgresql://localhost:5432/naomi_bot'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Azure Services Configuration
    AZURE_EVENT_HUB_CONNECTION_STR = os.environ.get('AZURE_EVENT_HUB_CONNECTION_STR')
    AZURE_EVENT_HUB_NAME = os.environ.get('AZURE_EVENT_HUB_NAME') or 'naomi-tweets'
    AZURE_STORAGE_CONNECTION_STR = os.environ.get('AZURE_STORAGE_CONNECTION_STR')
    
    # Redis Configuration (for Celery)
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # Bot Configuration
    BOT_USERNAME = os.environ.get('BOT_USERNAME') or 'naomi_data_sage'
    MAX_CONVERSATION_LENGTH = 3
    
    # Data Pipeline Configuration
    BATCH_PROCESSING_SCHEDULE = '0 2 * * *'  # Daily at 2 AM
    SENTIMENT_ANALYSIS_ENABLED = True
    
    @classmethod
    def validate_config(cls):
        """Validate that all required configuration is present"""
        required_vars = [
            'TWITTER_CLIENT_ID',
            'TWITTER_CLIENT_SECRET',
            'DATABASE_URL'
        ]
        
        missing_vars = [var for var in required_vars if not getattr(cls, var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        return True