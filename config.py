#!/usr/bin/env python3
"""
Configuration file support for SMTP Spray Tool.
Allows loading settings from YAML/JSON config files.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any


@dataclass
class TargetConfig:
    """Target server configuration"""
    host: str
    port: int = 587
    ssl: bool = False
    starttls: bool = True
    timeout: int = 30


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    delay_between_attempts: float = 1.0
    delay_between_users: float = 0.5
    delay_between_passwords: float = 1800.0  # 30 minutes
    jitter_min: float = 0.1
    jitter_max: float = 0.5
    max_attempts_per_user: int = 3
    lockout_threshold: int = 5


@dataclass
class OutputConfig:
    """Output configuration"""
    log_file: Optional[str] = None
    output_file: Optional[str] = None
    progress_file: Optional[str] = None
    verbose: bool = False


@dataclass
class SprayConfig:
    """Complete spray configuration"""
    target: TargetConfig
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    usernames: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    username_file: Optional[str] = None
    password_file: Optional[str] = None
    auth_method: str = "AUTO"
    mode: str = "spray"
    enum_method: str = "RCPT"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SprayConfig':
        """Create config from dictionary"""
        target_data = data.get('target', {})
        target = TargetConfig(
            host=target_data.get('host', ''),
            port=target_data.get('port', 587),
            ssl=target_data.get('ssl', False),
            starttls=target_data.get('starttls', True),
            timeout=target_data.get('timeout', 30)
        )

        rate_data = data.get('rate_limit', {})
        rate_limit = RateLimitConfig(
            delay_between_attempts=rate_data.get('delay_between_attempts', 1.0),
            delay_between_users=rate_data.get('delay_between_users', 0.5),
            delay_between_passwords=rate_data.get('delay_between_passwords', 1800.0),
            jitter_min=rate_data.get('jitter_min', 0.1),
            jitter_max=rate_data.get('jitter_max', 0.5),
            max_attempts_per_user=rate_data.get('max_attempts_per_user', 3),
            lockout_threshold=rate_data.get('lockout_threshold', 5)
        )

        output_data = data.get('output', {})
        output = OutputConfig(
            log_file=output_data.get('log_file'),
            output_file=output_data.get('output_file'),
            progress_file=output_data.get('progress_file'),
            verbose=output_data.get('verbose', False)
        )

        return cls(
            target=target,
            rate_limit=rate_limit,
            output=output,
            usernames=data.get('usernames', []),
            passwords=data.get('passwords', []),
            username_file=data.get('username_file'),
            password_file=data.get('password_file'),
            auth_method=data.get('auth_method', 'AUTO'),
            mode=data.get('mode', 'spray'),
            enum_method=data.get('enum_method', 'RCPT')
        )

    @classmethod
    def from_json_file(cls, filepath: str) -> 'SprayConfig':
        """Load config from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_yaml_file(cls, filepath: str) -> 'SprayConfig':
        """Load config from YAML file"""
        try:
            import yaml
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
            return cls.from_dict(data)
        except ImportError:
            raise ImportError("PyYAML is required for YAML config files. Install with: pip install pyyaml")

    @classmethod
    def load(cls, filepath: str) -> 'SprayConfig':
        """Auto-detect and load config file"""
        ext = Path(filepath).suffix.lower()
        if ext in ['.yaml', '.yml']:
            return cls.from_yaml_file(filepath)
        elif ext == '.json':
            return cls.from_json_file(filepath)
        else:
            # Try JSON first, then YAML
            try:
                return cls.from_json_file(filepath)
            except json.JSONDecodeError:
                return cls.from_yaml_file(filepath)

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'target': {
                'host': self.target.host,
                'port': self.target.port,
                'ssl': self.target.ssl,
                'starttls': self.target.starttls,
                'timeout': self.target.timeout
            },
            'rate_limit': {
                'delay_between_attempts': self.rate_limit.delay_between_attempts,
                'delay_between_users': self.rate_limit.delay_between_users,
                'delay_between_passwords': self.rate_limit.delay_between_passwords,
                'jitter_min': self.rate_limit.jitter_min,
                'jitter_max': self.rate_limit.jitter_max,
                'max_attempts_per_user': self.rate_limit.max_attempts_per_user,
                'lockout_threshold': self.rate_limit.lockout_threshold
            },
            'output': {
                'log_file': self.output.log_file,
                'output_file': self.output.output_file,
                'progress_file': self.output.progress_file,
                'verbose': self.output.verbose
            },
            'usernames': self.usernames,
            'passwords': self.passwords,
            'username_file': self.username_file,
            'password_file': self.password_file,
            'auth_method': self.auth_method,
            'mode': self.mode,
            'enum_method': self.enum_method
        }

    def save_json(self, filepath: str):
        """Save config to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def save_yaml(self, filepath: str):
        """Save config to YAML file"""
        try:
            import yaml
            with open(filepath, 'w') as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False)
        except ImportError:
            raise ImportError("PyYAML is required for YAML config files")


# Default configurations for common scenarios
CONFIGS = {
    'aggressive': RateLimitConfig(
        delay_between_attempts=0.5,
        delay_between_users=0.2,
        delay_between_passwords=300,  # 5 minutes
        jitter_min=0.1,
        jitter_max=0.2,
        max_attempts_per_user=5,
        lockout_threshold=5
    ),
    'normal': RateLimitConfig(
        delay_between_attempts=1.0,
        delay_between_users=0.5,
        delay_between_passwords=1800,  # 30 minutes
        jitter_min=0.1,
        jitter_max=0.5,
        max_attempts_per_user=3,
        lockout_threshold=5
    ),
    'stealth': RateLimitConfig(
        delay_between_attempts=5.0,
        delay_between_users=2.0,
        delay_between_passwords=3600,  # 1 hour
        jitter_min=0.3,
        jitter_max=1.0,
        max_attempts_per_user=2,
        lockout_threshold=3
    ),
    'paranoid': RateLimitConfig(
        delay_between_attempts=30.0,
        delay_between_users=10.0,
        delay_between_passwords=7200,  # 2 hours
        jitter_min=0.5,
        jitter_max=2.0,
        max_attempts_per_user=1,
        lockout_threshold=2
    )
}


def get_preset_config(preset: str) -> RateLimitConfig:
    """Get a preset rate limit configuration"""
    if preset not in CONFIGS:
        raise ValueError(f"Unknown preset: {preset}. Available: {list(CONFIGS.keys())}")
    return CONFIGS[preset]
