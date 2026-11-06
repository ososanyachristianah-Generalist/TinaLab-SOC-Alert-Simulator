# TinaLab SOC Alert Simulator

A small, offline **learning project** that reads simulated login logs and flags a source IP with at least **5 failed logins inside a rolling 60-second window**.

It is designed for beginner practice in log analysis and detection logic. It does not connect to a real network or monitor live systems.

## What it does

- Reads one log event per line.
- Counts `LOGIN FAILED` events separately for each source IP.
- Triggers an alert when the configured threshold is reached inside the rolling time window.
- Sorts events by timestamp before checking them.
- Treats the start of the time window as inclusive: an event exactly on the boundary still counts.
- Ignores blank lines and lines beginning with `#`.
- Reports malformed log rows with an error message.
- Validates and normalizes source IP addresses before counting events.

A successful login does **not** reset earlier failures in this prototype. That is a deliberate simplification for this exercise, not a universal detection rule.

## Requirements

- Python 3.8 or newer (no third-party Python packages required).
- Android users can run it in Termux; a computer with Python also works.
- Internet is not needed to run the simulator after Python is installed.

## Android / Termux setup

You can run TinaLab directly on Android using Termux.

1. Install [Termux](https://termux.dev/) if you have not already.
2. Install Git and Python:

```bash
pkg update
pkg install git python
```

3. Clone this repository:

```bash
git clone https://github.com/ososanyachristianah-Generalist/TinaLab-SOC-Alert-Simulator.git
```

4. Enter the project directory:

```bash
cd TinaLab-SOC-Alert-Simulator
```

No ZIP download or third-party Python packages are required.

## Run the simulator

From the project root (the folder containing `soc.py`):

```sh
python soc.py
```

The default sample should produce an alert for `192.168.1.20`. You can also pass a scenario file explicitly:

```sh
python soc.py scenarios/01_alert.txt
python soc.py scenarios/02_spread_out.txt
python soc.py scenarios/03_mixed_ips.txt
```

Change the time window or threshold:

```sh
python soc.py scenarios/01_alert.txt --window 30
python soc.py scenarios/01_alert.txt --window 120 --threshold 5
python soc.py scenarios/01_alert.txt --window 60 --threshold 3
```

- `--window` is measured in seconds.
- `--threshold` is the number of failed logins needed for an alert.
- Both values must be positive integers.

## Run the tests

From the project root (the folder containing `soc.py`):

```sh
python -m unittest -v
```

The 23 tests cover the included scenarios, rolling-window boundaries, events arriving out of order, successful logins, custom thresholds, malformed input, invalid IP addresses, IP address normalization, and command-line error handling. The expected result is **23 passing tests**.

## Understand the included scenarios

| File | Expected result | Why |
| --- | --- | --- |
| `scenarios/01_alert.txt` | Alert | Five failed logins from one IP occur within 20 seconds. |
| `scenarios/02_spread_out.txt` | No alert | The five failures are 40 seconds apart; no 60-second window contains five of them. |
| `scenarios/03_mixed_ips.txt` | No alert | Failed logins are split between two IP addresses, and each IP is counted separately. |

Try changing `--window` and `--threshold` and predict the result before running the command.

## Log format for your own practice data

Each non-comment line must use this format:

```text
YYYY-MM-DD HH:MM:SS | SOURCE_IP | LOGIN FAILED
YYYY-MM-DD HH:MM:SS | SOURCE_IP | LOGIN SUCCESS
```

For example, save fabricated events in `mylogs.txt`, then run:

```sh
python soc.py mylogs.txt --window 60 --threshold 5
```

Use fictional or otherwise authorized sample data only.

## Limits and safety

This is an illustrative offline detector, not a production SOC tool. It validates IP address syntax, but it does not verify that an address belongs to a real device or identify an actual attacker. It does not ingest live logs or correlate activity across multiple IP addresses. It reports the first alert it finds and uses a simplified detection rule that may produce false positives or false negatives. Do not use it as the sole basis for a real security decision.

## Project structure

- `soc.py` — detection logic and command-line interface.
- `test_soc.py` — automated unit tests.
- `scenarios/` — sample login logs for testing different outcomes.
- `.gitignore` — excludes generated files and local development artifacts.

## Example output

Running `python soc.py` with the default scenario produces output similar to this:

    TinaLab SOC Alert Simulator | threshold=5 | window=60s
    ALERT: Suspicious login activity detected!
    Source IP: 192.168.1.20
    Failed attempts in window: 5
    Window ends at: 2026-10-28 10:00:25

This example shows five failed login attempts from one source IP within the configured time window. Output depends on the input log and selected options.
