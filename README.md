# Cyber Log Triage

A defensive Java CLI for reviewing authentication-event CSV files and highlighting patterns worth investigating. The project demonstrates input validation, time-window analysis, JSON output, and automated tests without connecting to or changing any real system.

## Detections

- Repeated failed logins against one account from one source IP within a time window.
- A possible password spray: failed logins against several distinct accounts from one source IP within the window.
- A successful login after repeated failures for the same account and source IP.

These are triage signals, not proof of compromise. The tool does not label an IP address or account as malicious.

## Requirements

- JDK 17 or newer
- Maven 3.8 or newer

## Run

Build and test the project:

```bash
mvn test
```

Run the sample dataset:

```bash
mvn clean package
java -jar target/cyber-log-triage-1.0.0.jar sample_logs.csv
```

The sample events use documentation-only IP ranges: `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.

Print JSON for scripting:

```bash
java -jar target/cyber-log-triage-1.0.0.jar sample_logs.csv --json
```

Set a threshold and time window in minutes:

```bash
java -jar target/cyber-log-triage-1.0.0.jar sample_logs.csv --threshold 4 --window 15
```

The CLI exits with code `1` when it finds alerts, `0` when no patterns match, and `2` for invalid input or file errors.

## CSV format

Required columns are `timestamp`, `username`, `source_ip`, and `result`:

```csv
timestamp,username,source_ip,result
2026-10-22T09:00:00Z,alice,192.0.2.44,failure
2026-10-22T09:01:00Z,alice,192.0.2.44,success
```

Timestamps use ISO 8601; timestamps without a timezone are treated as UTC. Results must be `success` or `failure`. IPv4 and IPv6 addresses are validated.

## Design and scope

- Events are sorted by timestamp, so input row order does not affect analysis.
- Detection uses a sliding window grouped by source IP.
- CSV fields may be quoted and can contain commas.
- Apache Commons CSV handles input, and Jackson formats JSON output.
- The project is for learning and demonstration, not a replacement for a SIEM or incident-response process. It does not ingest system logs, block traffic, or make attribution claims.
