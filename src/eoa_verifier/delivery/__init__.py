"""Signed status-event HTTP delivery and its bounded retry policy.

Signature mechanics, HTTP client lifetime and application progression have
separate owners. The sender reads dedicated durable phases, never history scans.
"""

# Minimum seconds between ordinary webhook starts; failure backoff is independent.
DEFAULT_INTERVAL = 0.005
