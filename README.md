# Naomi - Data-Driven Twitter Bot

A Twitter bot with a unique personality: a Gen Z data engineer with old English charm. Naomi analyzes sentiment, engages with mentions, and posts data-driven insights.

## Features

- **Twitter OAuth 2.0 PKCE** - Secure authentication flow
- **Sentiment Analysis** - TextBlob-powered emotion detection for context-aware responses
- **Personality Engine** - Blends Gen Z slang ("no cap", "slay") with old English ("methinks", "verily")
- **Background Processing** - Celery tasks for mention handling and scheduled posts
- **Analytics Dashboard** - Track interactions, sentiment scores, and engagement

## Tech Stack

- **Backend:** Flask 2.3, SQLAlchemy
- **Database:** PostgreSQL (Azure)
- **Task Queue:** Celery + Redis
- **NLP:** TextBlob, NLTK
- **Deployment:** Azure App Service + GitHub Actions

## Quick Start

### Prerequisites

- Python 3.10+
- Redis server
- PostgreSQL database
- Twitter Developer account with OAuth 2.0 credentials

### Installation

```bash
# Clone the repository
git clone git@github.com:untitled114/Naomi-bot.git
cd Naomi-bot

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file:

```env
FLASK_SECRET_KEY=your-secret-key
TWITTER_CLIENT_ID=your-twitter-client-id
TWITTER_CLIENT_SECRET=your-twitter-client-secret
TWITTER_REDIRECT_URI=http://localhost:5000/callback
DATABASE_URL=postgresql://user:pass@localhost:5432/naomi
REDIS_URL=redis://localhost:6379/0
```

### Running Locally

```bash
# Terminal 1: Start Flask
python app.py

# Terminal 2: Start Celery worker
celery -A app.celery_app worker --loglevel=info

# Terminal 3: Start Celery Beat (scheduled tasks)
celery -A app.celery_app beat --loglevel=info
```

Visit `http://localhost:5000` and authenticate with Twitter.

## API Endpoints

### Public

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Homepage with OAuth login |
| `/health` | GET | Health check |
| `/bot/status` | GET | Bot status and stats |

### Authenticated

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/bot/process-mentions` | POST | Process and reply to mentions |
| `/bot/post-content` | POST | Post scheduled content |
| `/bot/interactions` | GET | List recent interactions |
| `/bot/stats` | GET | Analytics dashboard |
| `/bot/task-status/<id>` | GET | Check async task status |

Add `?async=true` to POST endpoints for background processing.

## Project Structure

```
naomi-twitter-bot/
├── app.py              # Flask app, routes, Celery tasks
├── config.py           # Configuration management
├── bot/
│   ├── naomi_bot.py    # Main bot logic & personality
│   ├── twitter_client.py # Tweepy wrapper
│   └── sentiment.py    # Sentiment analysis
├── data/
│   ├── models.py       # Data models
│   └── pipeline.py     # Data processing
├── templates/          # Jinja2 templates
└── requirements.txt
```

## Naomi's Personality

Naomi responds based on detected sentiment:

- **Negative sentiment:** Empathetic responses with encouragement
- **Positive sentiment:** Celebratory reactions ("Slay! Absolutely understood the assignment!")
- **Data topics:** Enthusiastic engagement with philosophical quotes
- **General:** Mix of Gen Z and old English phrases

Example responses:
- *"Methinks there's more to explore here. The data confirms it!"*
- *"No cap, this made my day! Statistical probability of awesome: 100%"*
- *"Verily, I say unto thee: check thy data quality."*

## Deployment

Automatically deploys to Azure App Service on push to `main` via GitHub Actions.

## License

MIT License - see [LICENSE](LICENSE)
