"""TinaLab SOC Alert Simulator v1. Offline simulated log analysis."""
import argparse
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

FMT = '%Y-%m-%d %H:%M:%S'

def analyze(lines, threshold=5, window_seconds=60):
    if threshold < 1 or window_seconds < 1:
        raise ValueError('threshold and window must be positive')
    records = []
    for number, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        parts = raw.split(' | ')
        if len(parts) != 3:
            raise ValueError(f'Line {number}: expected TIMESTAMP | IP | EVENT')
        stamp, ip, event = parts
        try:
            when = datetime.strptime(stamp, FMT)
        except ValueError as exc:
            raise ValueError(f'Line {number}: invalid timestamp: {stamp}') from exc
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError as exc:
            raise ValueError(f'Line {number}: invalid IP address: {ip}') from exc
        if event not in ('LOGIN FAILED', 'LOGIN SUCCESS'):
            raise ValueError(f'Line {number}: invalid event: {event}')
        records.append((when, ip, event))
    records.sort(key=lambda x: x[0])
    windows = defaultdict(deque)
    for when, ip, event in records:
        if event != 'LOGIN FAILED':
            continue
        queue = windows[ip]
        queue.append(when)
        start = when - timedelta(seconds=window_seconds)
        while queue and queue[0] < start:
            queue.popleft()
        if len(queue) >= threshold:
            return {'alert': True, 'ip': ip, 'count': len(queue), 'end': when}
    return {'alert': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logfile', nargs='?', default=str(Path(__file__).parent / 'scenarios' / '01_alert.txt'))
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=60, help='Window in seconds (default: 60)')
    args = parser.parse_args()
    try:
        lines = Path(args.logfile).read_text(encoding='utf-8').splitlines()
        result = analyze(lines, args.threshold, args.window)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'ERROR: {exc}\n')
    print(f'TinaLab SOC Alert Simulator | threshold={args.threshold} | window={args.window}s')
    if result['alert']:
        print('ALERT: Suspicious login activity detected!')
        print('Source IP:', result['ip'])
        print('Failed attempts in window:', result['count'])
        print('Window ends at:', result['end'].strftime(FMT))
    else:
        print('STATUS: No alert triggered.')

if __name__ == '__main__':
    main()
