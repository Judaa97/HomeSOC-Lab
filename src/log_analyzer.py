from collections import Counter
from pathlib import Path
import re
import sys

FAILED_LOGIN = re.compile(
	r"FAILED_LOGIN\s+user=(\S+)\s+ip=(\S+)"
)

THRESHOLD = 3


def analyze_log(log_path: str) -> list[dict]:
	"""Find IP address with repeated failed login events."""
	counts = Counter()

	with Path(log_path).open("r", encoding="utf-8") as log_file:
		for line in log_file:
			match = FAILED_LOGIN.search(line)

			if match:
				_username, ip_address = match.groups()
				counts[ip_address] += 1

	alerts = []

	for ip_address, count in sorted(counts.items()):
		if count >= THRESHOLD:
			alerts.append({
				"type": "repeated_failed_logins",
				"ip": ip_address,
				"count": count,
				"severity": "medium",
			})

	return alerts


def main() -> None:
	if len(sys.argv) != 2:
		print ("Usage: python src/log_analyzer.py PATH_TO_LOG")
		raise SystemExit(2)

	try:
		alerts = analyze_log(sys.argv[1])
	except OSError as error:
		print (f"Could not read log: {error}")
		raise SystemExit(1)

	if not alerts:
		print ("No alerts detected.")
		return

	for alert in  alerts:
		print (
			f"[{alert['severity'].upper()}] "
			f"{alert['type']}: IP={alert['ip']}, "
			f"failed logins={alert['count']}"
		)
if __name__ == "__main__":
	main()

