from src.log_analyzer import analyze_log

def test_detects_repeated_failed_logins(tmp_path):
	log = tmp_path / "auth.log"
	log.write_text(
		"FAILED_LOGIN user=a ip=192.0.2.10\n"
		"FAILED_LOGIN user=b ip=192.0.2.10\n"
		"FAILED_LOGIN user=c ip=192.0.2.10\n",
		encoding="utf-8",
	)

	alerts = analyze_log(str(log))

	assert len(alerts) == 1
	assert alerts[0]["ip"] == "192.0.2.10"
	assert alerts[0]["count"] == 3


def test_does_not_alert_below_threshold(tmp_path):
	log = tmp_path / "auth.log"
	log.write_text(
		"FAILED_LOGIN user=a ip= 192.0.2.10\n"
		"FAILED_LOGIN user=b ip=192.0.2.10\n",
		encoding="utf-8",
	)

	assert analyze_log(str(log)) == []

def test_ignores_successful_logins(tmp_path):
	log = tmp_path / "auth.log"
	log.write_text(
		"SUCCESS_LOGIN user=a ip=192.0.2.10\n",
		encoding="utf-8",
	)

	assert analyze_log(str(log)) == []

def test_detects_success_after_repeated_failed_logins(tmp_path):
	log = tmp_path / "auth.log"
	log.write_text(
		"FAILED_LOGIN user=alice ip=192.0.2.10\n"
		"FAILED_LOGIN user=alice ip=192.0.2.10\n"
		"FAILED_LOGIN user=alice ip=192.0.2.10\n"
		"SUCCESS_LOGIN user=alice ip=192.0.2.10\n",
		encoding="utf-8",
	)

	alerts = analyze_log(str(log))

	assert any(
		alert["type"] == "possible_brute_force_success"
		and alert["ip"] == "192.0.2.10"
		for alert in alerts
	)
