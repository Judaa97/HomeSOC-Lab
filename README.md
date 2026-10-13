HomeSOC-Lab

A small Python-based Security Operations Center(SOC) lab project for learning log analysis, basic
detection engineering and automated testing.

Project goals
- Analyze authentication log entries.
- Detect repeated failed login attempts from the same IP address.
- Generate simple security alerts.
- Test detection logic using automated unit tests.
- Build practical cybersecurity and Python skills.

Current features
- Parses synthetic authemtication logs.
- Counts failed login attempts by IP address.
- Generates a medium-severity alert when an IP address reaches three failed attempts.
- Ignores successful login events for this detection rule.
- Includes automated tests using pytest.

Requirements
- Python 3.10 or newer
- pytest

Setup
Clone or download the project, then run these commands from the project directory:

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

Usage
Run the log analyzer:

python src/log_analyzer.py sample_logs/auth.log

Example output:
[MEDIUM] repeated_failed_logins: IP=192.0.2.10, failed logins=3

Tests
Run the automated tests:

python -m pytest -v

Sample data
The included authentication log user reserved example IP addresses and synthetic events. It does
not contain real user authentication data.

Planned improvements
- Improve log parsing and error handling.
- Add more detection rules.
- Analyze selected Linux authentication logs.
- Document detection logic and test coverage.

Disclaimer
This project is intended for educational use. The sample logs are synthetic and are not evidence
of real security incidents.
