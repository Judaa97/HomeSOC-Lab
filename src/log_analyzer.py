from collections import Counter, defaultdict
from pathlib import Path
import re
import sys

FAILED_LOGIN = re.compile(
	r"FAILED_LOGIN\s+user=(\S+)\s+ip=(\S+)"
)

SUCCESS_LOGIN = re.compile(
	r"SUCCESS_LOGIN\s+user=(\S+)\s+ip=(\S+)"
)

THRESHOLD = 3


def analyze_log(log_path: str) -> list[dict]:
	"""Find IP address with repeated failed login events."""
	failed_counts = Counter()
	successful_after_threshold = set()

	with Path(log_path).open("r", encoding="utf-8") as log_file:
		for line in log_file:
			failed_match = FAILED_LOGIN.search(line)
			success_match = SUCCESS_LOGIN.search(line)

			if failed_match:
				_username, ip_address = failed_match.groups()
				failed_counts[ip_address] += 1

			elif success_match:
				_username, ip_address = success_match.groups()

				if failed_counts[ip_address] >= THRESHOLD:
					successful_after_threshold.add(ip_address)

	alerts = []

	for ip_address, count in sorted(failed_counts.items()):
		if count >= THRESHOLD:
			alerts.append({
				"type": "repeated_failed_logins",
				"ip": ip_address,
				"count": count,
				"severity": "medium",
			})

	for ip_address in sorted(successful_after_threshold):
		alerts.append({
			"type": "possible_brute_force_success",
			"ip": ip_address,
			"severity": "high",
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
			f"{alert['type']}: IP={alert['ip']},"
			+ (
			f"failed logins={alert['count']}"
			if "count" in alert else ""
			)
		)
if __name__ == "__main__":
	main()

