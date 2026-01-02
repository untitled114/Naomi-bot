# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Naomi** - A Twitter bot with OAuth 2.0 PKCE authentication, deployed on Azure App Service. The bot features a Gen Z engineer persona with data analytics capabilities and sentiment analysis.

## Tech Stack

- **Backend**: Flask 2.3, SQLAlchemy
- **Database**: Azure PostgreSQL
- **Auth**: Twitter OAuth 2.0 with PKCE
- **Async Tasks**: Celery + Redis
- **Azure Services**: Event Hub, Blob Storage
- **NLP**: TextBlob for sentiment analysis

## Development Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python app.py

# Run with gunicorn (production-like)
gunicorn --bind 0.0.0.0:5000 app:app
```

## Environment Variables

Required (set in `.env` or Azure App Settings):
- `TWITTER_CLIENT_ID` - Twitter OAuth client ID
- `TWITTER_CLIENT_SECRET` - Twitter OAuth client secret
- `DATABASE_URL` - PostgreSQL connection string
- `FLASK_SECRET_KEY` - Flask session secret

Optional:
- `TWITTER_REDIRECT_URI` - OAuth callback URL (defaults to Azure deployment URL)
- `REDIS_URL` - Redis for Celery (defaults to localhost)
- `AZURE_EVENT_HUB_CONNECTION_STR` / `AZURE_EVENT_HUB_NAME`
- `AZURE_STORAGE_CONNECTION_STR`

## Architecture

```
app.py              # Main Flask app with OAuth routes and DB models
config.py           # Configuration class loading from environment
bot/                # Bot logic (placeholder modules)
  ├── naomi_bot.py      # Main bot logic
  ├── twitter_client.py # Twitter API wrapper
  └── sentiment.py      # Sentiment analysis
data/               # Data pipeline (placeholder modules)
  ├── models.py         # Data models
  └── pipeline.py       # Processing pipeline
templates/          # Jinja2 templates for OAuth flow UI
```

## Key Routes

**OAuth:**
- `/` - Homepage with OAuth login
- `/login` - Initiates Twitter OAuth 2.0 PKCE flow
- `/callback` - OAuth callback handler
- `/logout` - Clear session

**Bot Control (require auth):**
- `POST /bot/process-mentions` - Process and reply to mentions (add `?async=true` for background)
- `POST /bot/post-content` - Post scheduled content (add `?async=true` for background)
- `GET /bot/task-status/<task_id>` - Check Celery task status
- `GET /bot/interactions` - Get recent interactions (optional: `?limit=N&type=reply|post`)
- `GET /bot/stats` - Bot analytics (counts, avg sentiment)

**Utility:**
- `/health` - Health check (tests DB connection)
- `/bot/status` - Bot status (public)
- `/debug/env` - Environment debug (remove in production)

## Database Models

Defined in `app.py`:
- `TwitterAuth` - Stores user OAuth tokens (access_token, refresh_token)
- `TweetInteraction` - Tweet analytics (tweet_id, interaction_type, sentiment_score)

## Running with Celery (Background Tasks)

```bash
# Terminal 1: Run Celery worker
celery -A app.celery_app worker --loglevel=info

# Terminal 2: Run Celery Beat (scheduled tasks)
celery -A app.celery_app beat --loglevel=info

# Terminal 3: Run Flask app
python app.py
```

**Scheduled Tasks:**
- `task_process_mentions` - Every 5 minutes
- `task_post_scheduled_content` - Every 4 hours

## Deployment

Deploys automatically to Azure via GitHub Actions on push to `main`. The workflow is in `.github/workflows/azure-webapps-python.yml`.

Azure Web App name: `naomi`
