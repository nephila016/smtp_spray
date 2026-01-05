# SMTP Spray Tool

A comprehensive SMTP password spraying and brute force tool for **authorized penetration testing engagements**.

## Features

- **Multi-Port Support**: Ports 25 (SMTP), 465 (SMTPS), 587 (Submission)
- **Encryption**: Plain, STARTTLS, Implicit SSL/TLS
- **Authentication Methods**: PLAIN, LOGIN, CRAM-MD5, AUTO-detection
- **Attack Modes**: Password Spray (recommended), Brute Force
- **User Enumeration**: VRFY, EXPN, RCPT TO methods
- **Rate Limiting**: Configurable delays, jitter, per-user attempt limits
- **Lockout Detection**: Automatic detection and user skipping
- **Progress Tracking**: Save/resume capability for long-running sprays
- **Detailed Logging**: Full audit trail for engagement reports

## Installation

```bash
# Clone or copy the tool
cd smtp_spray

# Install optional dependencies
pip install -r requirements.txt

# Or minimal install (no external dependencies needed for core functionality)
python smtp_spray.py --help
```

## Quick Start

### Basic Password Spray (Port 587 with STARTTLS)

```bash
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt
```

### User Enumeration First

```bash
# Enumerate valid users via RCPT TO
python smtp_spray.py -t mail.target.com -U users.txt --enumerate -o valid_users.txt

# Then spray only valid users
python smtp_spray.py -t mail.target.com -U valid_users.txt -P passwords.txt
```

### Different Ports and Encryption

```bash
# Port 25 (no encryption)
python smtp_spray.py -t mail.target.com -p 25 --no-tls -U users.txt -P passwords.txt

# Port 465 (Implicit SSL)
python smtp_spray.py -t mail.target.com --ssl -U users.txt -P passwords.txt

# Port 587 (STARTTLS) - default
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt
```

## Usage Examples

### Password Spraying (Recommended)

Password spraying tests one password against all users before moving to the next password. This minimizes lockout risk.

```bash
# Standard spray with 30-minute delay between password rounds
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt \
    --mode spray --spray-delay 1800

# Stealth mode - longer delays
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt \
    --delay 5 --spray-delay 3600 --jitter 0.5

# Single password test
python smtp_spray.py -t mail.target.com -U users.txt --password "Summer2025!"
```

### Brute Force Mode

**WARNING**: Brute force has higher lockout risk. Use spray mode when possible.

```bash
# All passwords against single user
python smtp_spray.py -t mail.target.com -u admin@target.com -P passwords.txt --mode brute
```

### User Enumeration

```bash
# RCPT TO method (most reliable, works even when VRFY/EXPN disabled)
python smtp_spray.py -t mail.target.com -U users.txt --enumerate --enum-method RCPT

# VRFY method
python smtp_spray.py -t mail.target.com -U users.txt --enumerate --enum-method VRFY

# EXPN method (mailing list expansion)
python smtp_spray.py -t mail.target.com -U users.txt --enumerate --enum-method EXPN
```

### Resume Interrupted Spray

```bash
# Spray will auto-save progress
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt

# If interrupted (Ctrl+C), resume with:
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt --resume
```

### Output and Logging

```bash
# Save valid credentials to file
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt -o valid_creds.txt

# Verbose output with log file
python smtp_spray.py -t mail.target.com -U users.txt -P passwords.txt \
    -v --log spray.log -o valid_creds.txt
```

## Command Line Options

```
Target Options:
  -t, --target        Target SMTP server (required)
  -p, --port          SMTP port (default: 587)
  --ssl               Use implicit SSL (port 465)
  --no-tls            Don't use STARTTLS (plain connection)
  --timeout           Connection timeout in seconds (default: 30)

Credentials:
  -u, --user          Single username to test
  -U, --userfile      File containing usernames
  -P, --passfile      File containing passwords
  --password          Single password to test

Attack Mode:
  --mode              Attack mode: spray or brute (default: spray)
  --auth              Auth method: AUTO, PLAIN, LOGIN, CRAM-MD5 (default: AUTO)

User Enumeration:
  --enumerate         Enumerate users instead of spraying
  --enum-method       Enumeration method: VRFY, EXPN, RCPT (default: RCPT)

Rate Limiting:
  --delay             Delay between attempts in seconds (default: 1.0)
  --spray-delay       Delay between password rounds in seconds (default: 1800)
  --jitter            Jitter factor 0-1 (default: 0.3)
  --max-attempts      Max attempts per user (default: 3)

Output Options:
  -o, --output        Output file for valid credentials
  --log               Log file path
  -v, --verbose       Verbose output

Resume:
  --resume            Resume from progress file
  --progress-file     Custom progress file path
```

## Rate Limiting Presets

The tool supports preset rate limiting configurations via the config module:

| Preset | Attempt Delay | Spray Delay | Max Attempts | Use Case |
|--------|--------------|-------------|--------------|----------|
| aggressive | 0.5s | 5 min | 5 | Internal testing |
| normal | 1.0s | 30 min | 3 | Standard engagement |
| stealth | 5.0s | 1 hour | 2 | Evasion required |
| paranoid | 30s | 2 hours | 1 | High-security targets |

## Utility Scripts

### MX Lookup and Port Scanning

```bash
python utils.py target.com
```

### Generate Usernames from Names

```python
from utils import generate_usernames_from_file
emails = generate_usernames_from_file('names.txt', 'target.com', 'users.txt')
```

### Generate Password Lists

```python
from utils import generate_seasonal_passwords, generate_company_passwords

# Season-based passwords
passwords = generate_seasonal_passwords(years=[2024, 2025])

# Company-based passwords
passwords = generate_company_passwords('Acme Corp', years=[2024, 2025])
```

## File Structure

```
smtp_spray/
├── smtp_spray.py       # Main tool
├── config.py           # Configuration support
├── utils.py            # Utility functions
├── requirements.txt    # Dependencies
├── config_example.json # Example config file
└── wordlists/
    ├── common_passwords.txt
    └── example_users.txt
```

## Best Practices

### Pre-Engagement

1. **Get written authorization** from the client
2. **Agree on testing hours** and acceptable lockout tolerance
3. **Test your methodology** on a test environment first
4. **Document the scope** - which users/domains are in scope

### During Spray

1. **Start with user enumeration** to reduce noise
2. **Use spray mode** (not brute force) to minimize lockouts
3. **Monitor for lockouts** - the tool detects common lockout responses
4. **Use appropriate delays** - 30+ minutes between password rounds
5. **Save progress** - use `--resume` if interrupted

### Lockout Avoidance

- **Max 3-5 passwords per user** across the entire engagement
- **30+ minute delays** between password rounds
- **Track all attempts** in your engagement notes
- **Stop immediately** if lockouts are detected

## Legal Disclaimer

This tool is provided for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always:

- Obtain **explicit written authorization** before testing
- Test only systems you own or have permission to test
- Follow your organization's security testing policies
- Comply with all applicable laws and regulations

The authors are not responsible for misuse of this tool.

## Troubleshooting

### Connection Errors

```bash
# Check if SMTP ports are open
python utils.py mail.target.com

# Try different ports
python smtp_spray.py -t mail.target.com -p 25 --no-tls ...
python smtp_spray.py -t mail.target.com -p 465 --ssl ...
```

### Authentication Errors

```bash
# Try specific auth method
python smtp_spray.py -t mail.target.com --auth PLAIN ...
python smtp_spray.py -t mail.target.com --auth LOGIN ...
```

### TLS Errors

Some servers have certificate issues. For testing purposes only, you can modify the SSL context in the code to disable verification (not recommended for production).

## References

- [HackTricks SMTP Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
- [OWASP Password Spraying](https://owasp.org/www-community/attacks/Password_Spraying_Attack)
- [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)
