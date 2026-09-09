from collections import defaultdict
from datetime import datetime, timezone, timedelta
import threading
from typing import Dict, List

from src.config import settings


class LoginRateLimiter:
    """
    In-memory sliding window rate limiter tracking failed login attempts
    per IP address and per email to prevent brute-force attacks.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window = timedelta(seconds=window_seconds)
        self._ip_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self._email_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self._lock = threading.Lock()

    def _clean_window(self, attempts: List[datetime], now: datetime) -> List[datetime]:
        cutoff = now - self.window
        return [ts for ts in attempts if ts > cutoff]

    def is_rate_limited(self, ip: str, email: str) -> bool:
        """Check if either IP or email has exceeded the attempt threshold."""
        now = datetime.now(timezone.utc)
        with self._lock:
            if ip:
                self._ip_attempts[ip] = self._clean_window(self._ip_attempts[ip], now)
                if len(self._ip_attempts[ip]) >= self.max_attempts:
                    return True

            if email:
                norm_email = email.strip().lower()
                self._email_attempts[norm_email] = self._clean_window(self._email_attempts[norm_email], now)
                if len(self._email_attempts[norm_email]) >= self.max_attempts:
                    return True

        return False

    def record_failure(self, ip: str, email: str) -> None:
        """Record a failed login attempt for both IP and email."""
        now = datetime.now(timezone.utc)
        with self._lock:
            if ip:
                self._ip_attempts[ip] = self._clean_window(self._ip_attempts[ip], now)
                self._ip_attempts[ip].append(now)

            if email:
                norm_email = email.strip().lower()
                self._email_attempts[norm_email] = self._clean_window(self._email_attempts[norm_email], now)
                self._email_attempts[norm_email].append(now)

    def record_success(self, ip: str, email: str) -> None:
        """Reset failed attempt counters on successful authentication."""
        with self._lock:
            if ip and ip in self._ip_attempts:
                del self._ip_attempts[ip]
            if email:
                norm_email = email.strip().lower()
                if norm_email in self._email_attempts:
                    del self._email_attempts[norm_email]

    def reset_all(self) -> None:
        """Clear all stored state (primarily for test isolation)."""
        with self._lock:
            self._ip_attempts.clear()
            self._email_attempts.clear()


login_rate_limiter = LoginRateLimiter(
    max_attempts=settings.LOGIN_RATE_LIMIT_ATTEMPTS,
    window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
)
