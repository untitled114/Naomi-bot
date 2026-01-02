"""Twitter API client wrapper using Tweepy."""

import tweepy
import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Tweet:
    """Represents a tweet."""
    id: str
    text: str
    author_id: str
    author_username: Optional[str] = None
    conversation_id: Optional[str] = None
    in_reply_to_user_id: Optional[str] = None


class TwitterClient:
    """Wrapper for Twitter API v2 operations."""

    def __init__(self, access_token: str):
        """
        Initialize the Twitter client with an OAuth2 access token.

        Args:
            access_token: User's OAuth2 access token
        """
        self.client = tweepy.Client(access_token)
        self._user_id: Optional[str] = None
        self._username: Optional[str] = None

    @property
    def user_id(self) -> str:
        """Get the authenticated user's ID."""
        if not self._user_id:
            self._fetch_user_info()
        return self._user_id

    @property
    def username(self) -> str:
        """Get the authenticated user's username."""
        if not self._username:
            self._fetch_user_info()
        return self._username

    def _fetch_user_info(self) -> None:
        """Fetch and cache the authenticated user's info."""
        try:
            me = self.client.get_me()
            if me.data:
                self._user_id = me.data.id
                self._username = me.data.username
        except tweepy.TweepyException as e:
            logger.error(f"Failed to fetch user info: {e}")
            raise

    def post_tweet(self, text: str, reply_to: Optional[str] = None) -> Optional[Tweet]:
        """
        Post a tweet.

        Args:
            text: The tweet content (max 280 chars)
            reply_to: Optional tweet ID to reply to

        Returns:
            Tweet object if successful, None otherwise
        """
        try:
            if len(text) > 280:
                text = text[:277] + "..."

            response = self.client.create_tweet(
                text=text,
                in_reply_to_tweet_id=reply_to
            )

            if response.data:
                logger.info(f"Posted tweet: {response.data['id']}")
                return Tweet(
                    id=response.data['id'],
                    text=text,
                    author_id=self.user_id
                )
            return None

        except tweepy.TweepyException as e:
            logger.error(f"Failed to post tweet: {e}")
            return None

    def get_mentions(self, since_id: Optional[str] = None, max_results: int = 10) -> list[Tweet]:
        """
        Get recent mentions of the authenticated user.

        Args:
            since_id: Only get mentions after this tweet ID
            max_results: Maximum number of mentions to return

        Returns:
            List of Tweet objects
        """
        mentions = []
        try:
            response = self.client.get_users_mentions(
                id=self.user_id,
                since_id=since_id,
                max_results=max_results,
                tweet_fields=['conversation_id', 'in_reply_to_user_id'],
                expansions=['author_id']
            )

            if response.data:
                # Build username lookup from includes
                usernames = {}
                if response.includes and 'users' in response.includes:
                    for user in response.includes['users']:
                        usernames[user.id] = user.username

                for tweet in response.data:
                    mentions.append(Tweet(
                        id=tweet.id,
                        text=tweet.text,
                        author_id=tweet.author_id,
                        author_username=usernames.get(tweet.author_id),
                        conversation_id=tweet.conversation_id,
                        in_reply_to_user_id=tweet.in_reply_to_user_id
                    ))

        except tweepy.TweepyException as e:
            logger.error(f"Failed to get mentions: {e}")

        return mentions

    def get_conversation(self, conversation_id: str, max_results: int = 20) -> list[Tweet]:
        """
        Get tweets in a conversation thread.

        Args:
            conversation_id: The conversation ID to fetch
            max_results: Maximum tweets to return

        Returns:
            List of Tweet objects in the conversation
        """
        tweets = []
        try:
            response = self.client.search_recent_tweets(
                query=f"conversation_id:{conversation_id}",
                max_results=max_results,
                tweet_fields=['conversation_id', 'in_reply_to_user_id'],
                expansions=['author_id']
            )

            if response.data:
                usernames = {}
                if response.includes and 'users' in response.includes:
                    for user in response.includes['users']:
                        usernames[user.id] = user.username

                for tweet in response.data:
                    tweets.append(Tweet(
                        id=tweet.id,
                        text=tweet.text,
                        author_id=tweet.author_id,
                        author_username=usernames.get(tweet.author_id),
                        conversation_id=tweet.conversation_id,
                        in_reply_to_user_id=tweet.in_reply_to_user_id
                    ))

        except tweepy.TweepyException as e:
            logger.error(f"Failed to get conversation: {e}")

        return tweets

    def like_tweet(self, tweet_id: str) -> bool:
        """
        Like a tweet.

        Args:
            tweet_id: ID of the tweet to like

        Returns:
            True if successful
        """
        try:
            self.client.like(tweet_id)
            return True
        except tweepy.TweepyException as e:
            logger.error(f"Failed to like tweet: {e}")
            return False
