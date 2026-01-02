"""Sentiment analysis module using TextBlob."""

from textblob import TextBlob
from dataclasses import dataclass


@dataclass
class SentimentResult:
    """Container for sentiment analysis results."""
    polarity: float  # -1.0 (negative) to 1.0 (positive)
    subjectivity: float  # 0.0 (objective) to 1.0 (subjective)
    label: str  # 'positive', 'negative', or 'neutral'
    confidence: float  # Strength of the sentiment


class SentimentAnalyzer:
    """Analyzes sentiment of text using TextBlob."""

    POSITIVE_THRESHOLD = 0.1
    NEGATIVE_THRESHOLD = -0.1

    def analyze(self, text: str) -> SentimentResult:
        """
        Analyze the sentiment of given text.

        Args:
            text: The text to analyze

        Returns:
            SentimentResult with polarity, subjectivity, label, and confidence
        """
        blob = TextBlob(text)
        polarity = blob.sentiment.polarity
        subjectivity = blob.sentiment.subjectivity

        if polarity > self.POSITIVE_THRESHOLD:
            label = 'positive'
        elif polarity < self.NEGATIVE_THRESHOLD:
            label = 'negative'
        else:
            label = 'neutral'

        confidence = abs(polarity)

        return SentimentResult(
            polarity=polarity,
            subjectivity=subjectivity,
            label=label,
            confidence=confidence
        )

    def get_emotion_context(self, result: SentimentResult) -> dict:
        """
        Get additional context about the emotional tone.

        Args:
            result: SentimentResult from analyze()

        Returns:
            Dict with emotion descriptors for response generation
        """
        context = {
            'is_emotional': result.subjectivity > 0.5,
            'intensity': 'strong' if result.confidence > 0.5 else 'mild',
            'needs_empathy': result.label == 'negative' and result.confidence > 0.3,
            'celebratory': result.label == 'positive' and result.confidence > 0.5,
        }
        return context
