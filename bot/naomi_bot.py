"""
Naomi Bot - A data-loving Gen Z Twitter bot with old English charm.

Personality traits:
- Smart engineer passionate about data analytics
- Gen Z communication style with occasional old English flair
- Sarcastic wit balanced with philosophical wisdom
- Empathetic and engaging in conversations
"""

import random
import logging
from typing import Optional
from datetime import datetime

from .twitter_client import TwitterClient, Tweet
from .sentiment import SentimentAnalyzer, SentimentResult

logger = logging.getLogger(__name__)


class NaomiBot:
    """Main bot class implementing Naomi's personality and behavior."""

    # Personality components
    GREETINGS = [
        "Greetings, fellow data enthusiast!",
        "Hey hey! Your friendly neighborhood data nerd here",
        "Salutations! Ready to dive into some numbers?",
        "'Tis I, Naomi, at thy service",
        "What's good! Let's talk data",
    ]

    OLD_ENGLISH_PHRASES = [
        "methinks",
        "perchance",
        "verily",
        "'tis",
        "forsooth",
        "prithee",
        "mayhaps",
    ]

    GEN_Z_PHRASES = [
        "no cap",
        "lowkey",
        "highkey",
        "fr fr",
        "slay",
        "it's giving",
        "understood the assignment",
        "main character energy",
        "rent free",
    ]

    DATA_TOPICS = [
        "data visualization",
        "machine learning",
        "statistical analysis",
        "data pipelines",
        "A/B testing",
        "predictive modeling",
        "data ethics",
        "real-time analytics",
    ]

    PHILOSOPHICAL_QUOTES = [
        "In data we trust, but verification is key",
        "Every outlier has a story to tell",
        "Correlation isn't causation, but it's a good conversation starter",
        "The best insights come from asking 'why' five times",
        "Data doesn't lie, but it can be misunderstood",
    ]

    def __init__(self, twitter_client: TwitterClient, max_conversation_length: int = 3):
        """
        Initialize Naomi bot.

        Args:
            twitter_client: Authenticated Twitter client
            max_conversation_length: Max replies in a single conversation thread
        """
        self.twitter = twitter_client
        self.sentiment = SentimentAnalyzer()
        self.max_conversation_length = max_conversation_length
        self.last_mention_id: Optional[str] = None

    def generate_response(self, tweet: Tweet, sentiment_result: SentimentResult) -> str:
        """
        Generate a response based on the incoming tweet and its sentiment.

        Args:
            tweet: The tweet to respond to
            sentiment_result: Sentiment analysis of the tweet

        Returns:
            Generated response text
        """
        emotion_context = self.sentiment.get_emotion_context(sentiment_result)
        text_lower = tweet.text.lower()

        # Handle different conversation contexts
        if emotion_context['needs_empathy']:
            response = self._generate_empathetic_response(tweet, sentiment_result)
        elif emotion_context['celebratory']:
            response = self._generate_celebratory_response(tweet)
        elif self._is_data_question(text_lower):
            response = self._generate_data_response(tweet)
        elif self._is_greeting(text_lower):
            response = self._generate_greeting_response(tweet)
        else:
            response = self._generate_general_response(tweet, sentiment_result)

        # Add personality flair
        response = self._add_personality_flair(response)

        # Ensure we mention the user
        if tweet.author_username:
            if not response.startswith(f"@{tweet.author_username}"):
                response = f"@{tweet.author_username} {response}"

        return response[:280]  # Twitter limit

    def _generate_empathetic_response(self, tweet: Tweet, sentiment: SentimentResult) -> str:
        """Generate an empathetic response for negative sentiment."""
        empathy_starters = [
            "I hear you, that sounds rough.",
            "Oof, that's not easy to deal with.",
            "Sending good vibes your way.",
            "That's valid, honestly.",
        ]

        encouragements = [
            "Data shows that tough times don't last forever!",
            "Remember: even messy data can tell a beautiful story eventually.",
            "Verily, this too shall pass (the data confirms it).",
            "You've got this, fr fr.",
        ]

        return f"{random.choice(empathy_starters)} {random.choice(encouragements)}"

    def _generate_celebratory_response(self, tweet: Tweet) -> str:
        """Generate a celebratory response for positive sentiment."""
        celebrations = [
            "LET'S GOOO! That's what I'm talking about!",
            "Slay! Absolutely understood the assignment!",
            "This is giving main character energy and I'm here for it!",
            "Verily, this doth bring joy to mine heart!",
            "No cap, this made my day!",
        ]

        additions = [
            "The data predicted greatness and here we are!",
            "Statistical probability of awesome: 100%",
            "Methinks this calls for celebration!",
            "*adds to positive outcomes dataset*",
        ]

        return f"{random.choice(celebrations)} {random.choice(additions)}"

    def _generate_data_response(self, tweet: Tweet) -> str:
        """Generate a response to data-related topics."""
        data_responses = [
            f"Ooh, {random.choice(self.DATA_TOPICS)}? Now we're talking my language!",
            f"Lowkey obsessed with this topic. {random.choice(self.PHILOSOPHICAL_QUOTES)}",
            f"Forsooth! Thou hast summoned my inner data nerd. Let me share some thoughts...",
            f"This is giving analytics energy! {random.choice(self.PHILOSOPHICAL_QUOTES)}",
            f"Perchance we could dive deeper into this? Data exploration is *chef's kiss*",
        ]
        return random.choice(data_responses)

    def _generate_greeting_response(self, tweet: Tweet) -> str:
        """Generate a greeting response."""
        return random.choice(self.GREETINGS)

    def _generate_general_response(self, tweet: Tweet, sentiment: SentimentResult) -> str:
        """Generate a general conversational response."""
        general_responses = [
            "Interesting perspective! Methinks there's more to explore here.",
            "Hmm, lowkey intrigued by this. Tell me more?",
            "This is rent free in my head now. Good point!",
            f"Verily, {random.choice(self.PHILOSOPHICAL_QUOTES).lower()}",
            "The data on this is fascinating, actually.",
            "No cap, I hadn't thought about it that way.",
        ]
        return random.choice(general_responses)

    def _add_personality_flair(self, response: str) -> str:
        """Add occasional personality elements to responses."""
        # 30% chance to add an emoji
        if random.random() < 0.3:
            emojis = ["📊", "✨", "💡", "🔥", "📈", "🤓", "💫", "🎯"]
            response = f"{response} {random.choice(emojis)}"

        return response

    def _is_data_question(self, text: str) -> bool:
        """Check if the tweet is about data topics."""
        data_keywords = [
            'data', 'analytics', 'statistics', 'machine learning', 'ml', 'ai',
            'visualization', 'python', 'sql', 'database', 'model', 'predict',
            'analysis', 'metric', 'dashboard', 'insight', 'algorithm'
        ]
        return any(keyword in text for keyword in data_keywords)

    def _is_greeting(self, text: str) -> bool:
        """Check if the tweet is a greeting."""
        greetings = ['hello', 'hi', 'hey', 'greetings', 'good morning',
                     'good evening', 'sup', 'yo', "what's up"]
        return any(greeting in text for greeting in greetings)

    def process_mentions(self) -> list[dict]:
        """
        Process new mentions and generate responses.

        Returns:
            List of interaction records for database storage
        """
        interactions = []
        mentions = self.twitter.get_mentions(since_id=self.last_mention_id)

        for mention in mentions:
            try:
                # Update last processed mention
                if not self.last_mention_id or mention.id > self.last_mention_id:
                    self.last_mention_id = mention.id

                # Analyze sentiment
                sentiment_result = self.sentiment.analyze(mention.text)

                # Generate and post response
                response_text = self.generate_response(mention, sentiment_result)
                response = self.twitter.post_tweet(response_text, reply_to=mention.id)

                if response:
                    # Like the mention as acknowledgment
                    self.twitter.like_tweet(mention.id)

                    interaction = {
                        'tweet_id': mention.id,
                        'response_id': response.id,
                        'interaction_type': 'reply',
                        'original_text': mention.text,
                        'response_text': response_text,
                        'sentiment_score': sentiment_result.polarity,
                        'sentiment_label': sentiment_result.label,
                        'user_mentioned': mention.author_username,
                        'conversation_id': mention.conversation_id,
                        'created_at': datetime.utcnow()
                    }
                    interactions.append(interaction)
                    logger.info(f"Replied to @{mention.author_username}: {response_text[:50]}...")

            except Exception as e:
                logger.error(f"Error processing mention {mention.id}: {e}")

        return interactions

    def post_scheduled_content(self) -> Optional[dict]:
        """
        Post scheduled content (data insights, thoughts, etc.)

        Returns:
            Interaction record if posted, None otherwise
        """
        content_templates = [
            f"Daily data thought: {random.choice(self.PHILOSOPHICAL_QUOTES)} 📊",
            f"Methinks {random.choice(self.DATA_TOPICS)} is underrated. Thoughts? 🤔",
            f"Hot take: {random.choice(self.PHILOSOPHICAL_QUOTES)} No cap. 🔥",
            f"Good morrow, fellow data enthusiasts! What are we analyzing today? ✨",
            f"Verily, I say unto thee: check thy data quality. 'Tis the foundation of all insights. 📈",
        ]

        content = random.choice(content_templates)
        tweet = self.twitter.post_tweet(content)

        if tweet:
            return {
                'tweet_id': tweet.id,
                'interaction_type': 'post',
                'content': content,
                'created_at': datetime.utcnow()
            }
        return None


def create_bot(access_token: str, max_conversation_length: int = 3) -> NaomiBot:
    """
    Factory function to create a NaomiBot instance.

    Args:
        access_token: Twitter OAuth2 access token
        max_conversation_length: Max replies per conversation

    Returns:
        Configured NaomiBot instance
    """
    client = TwitterClient(access_token)
    return NaomiBot(client, max_conversation_length)
