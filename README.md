# Anomaly Detection System – EN4720 (Milestone 4)

## Project Overview

This project implements an anomaly detection system for a cyber-physical system, developed for the EN4720 course (Semester 8, Milestone 4). The system monitors events such as login attempts, device toggles, and power readings, flagging suspicious activities based on predefined rules. It uses a class-based `Detector` to track state and log events in NDJSON format, with unit tests to verify functionality.

The system detects security issues like brute-force login attacks, device flipping, and power anomalies, without file locking or role-based access rules. It resolves prior issues, including missing logs, extra events, and incorrect power spike detection, by using a shared `Detector` state and custom test ordering.

---

## Files

### `detector.py`
**Purpose**: Defines the `Detector` class for event processing and anomaly detection.

**Key Components**:
- `__init__(events_log, alerts_log)`: Initializes log file paths and resets state.
- `reset_state()`: Clears in-memory tracking (e.g., `failed_login_attempts`, `power_readings`).
- `log_event(event, flagged, reason)`: Logs events to `logs/events.json` and alerts to `logs/alerts.json`.
- `instrument(event_name, user_role, user_id, source_id, timestamp, context)`: Analyzes events and applies detection rules.

**Detection Rules**:
1. **Failed Login Attempts**: Flags >5 failed logins within 1 minute per user.
2. **IP Diversity**: Flags logins from >3 unique IPs per user.
3. **Toggle Device Spam**: Flags >10 toggles within 30 seconds per user.
4. **After-Hours Toggle**: Flags non-ADMIN/MANAGER toggles outside 8 AM–6 PM.
5. **Device Flipping**: Flags >6 toggles of the same device within 30 seconds.
6. **Power Anomalies**: Flags power readings >150% of historical average or ≤0.

**Notes**:
- Uses `try-except` to handle I/O errors, preventing silent logging failures.
- Maintains state across tests for historical data (e.g., power readings).
- No file locking or role-based rules, per requirements.

---

### `test_cases.py`
**Purpose**: Contains unit tests to validate `Detector` functionality.

**Key Components**:
- `setUpClass`: Clears log files and creates a shared `Detector` instance.
- `setUp`: Sets test ID and base timestamp.
- `tearDown`: Prints logs on test failure (commented).
- `tearDownClass`: Verifies 30 events and resets `Detector` state.
- **Test Methods**: Eight tests for normal and attack scenarios.
- **Custom Test Suite**: Ensures specific test order.

**Test Cases**:
1. `test_normal_login_attempts`: 3 failed + 2 successful logins (5 events, no alerts).
2. `test_normal_toggle`: 5 device toggles (5 events, no alerts).
3. `test_normal_power_readings`: 5 power readings (100–105W, 5 events, no alerts).
4. `test_failed_login_attack`: 6 failed logins (6 events, alert on 6th).
5. `test_ip_diversity_attack`: Logins from 4 IPs (4 events, alert on 4th).
6. `test_after_hours_toggle`: Toggle at 11 PM (1 event, alerted).
7. `test_device_flipping_attack`: 7 toggles of one device (7 events, alert on 7th).
8. `test_power_spike_attack`: 200W and 0W readings (2 events, both alerted).

**Notes**:
- Shared `Detector` state enables `test_power_spike_attack` to use `test_normal_power_readings`’ average (~104.8W).
- Custom test order ensures state consistency.
- Assertions commented; enable with `test_id` tags for validation.

---

## Setup Instructions

### Prerequisites
- Python 3.6+
- No external dependencies

### Directory Structure
Milestone_4/
  
  ├── detector.py
  
  ├── test_cases.py/
  
  └── logs/
  
  ├── events.json (auto-created)
  
  └── alerts.json (auto-created)


### Installation
1. Clone or copy files to your machine.
2. Verify Python installation:
 ```bash
 python --version
```
3. Navigate to the project directory:
 ```bash
 https://github.com/malanban/EN4720_The_Infected_Crew_Milestone_04
```

### Usage
 #### Running Tests:
1. Clear logs (optional):
  ```bash
  del logs\events.json
  del logs\alerts.json
```
2. Run tests:
  ```bash
  python -m unittest test_cases.py -v
```

Expected Output:
```scss
test_normal_login_attempts (test_cases.TestDetector) ... ok
test_normal_toggle (test_cases.TestDetector) ... ok
test_normal_power_readings (test_cases.TestDetector) ... ok
test_failed_login_attack (test_cases.TestDetector) ... ok
test_device_flipping_attack (test_cases.TestDetector) ... ok
test_power_spike_attack (test_cases.TestDetector) ... ok
test_ip_diversity_attack (test_cases.TestDetector) ... ok
test_after_hours_toggle (test_cases.TestDetector) ... ok
----------------------------------------------------------------------
Ran 8 tests in 0.020s

OK
```

### Verifying Logs
1. Check total events (should be 30):
```bash
python -c "with open('logs/events.json', 'r') as f: print(len([line for line in f]))"
```

2. Inspect logs/events.json:
```bash
python -c "with open('logs/events.json', 'r') as f: [print(line.strip()) for line in f]"
```
3. Verify alerts in logs/alerts.json.


### Debugging Failures
1. Enable commented assertions in test_cases.py.

2. Uncomment tearDown/tearDownClass print statements.

3. Run a single test:
```bash
python -m unittest test_cases.TestDetector.test_power_spike_attack -v
```

### Implementation Notes
#### Shared Detector State
1. Single `Detector` instance in `setUpClass`.
2. State persists, `enabling test_power_spike_attack` to use `test_normal_power_readings` average.
3. Reset in `tearDownClass`.
4. Unique `user_id`/`source_id` prevents rule interference.

### Custom Test Order
#### Tests run in order:

1. `test_normal_login_attempts`
2. `test_normal_toggle`
3. `test_normal_power_readings`
4. `test_failed_login_attack`
5. `test_device_flipping_attack`
6. `test_power_spike_attack`
7. `test_ip_diversity_attack`
8. `test_after_hours_toggle`
Ensures `test_normal_power_readings` precedes `test_power_spike_attack`.

### Limitations
1. Shared state assumes test order.
2. No role-based rules or file locking.
3. Power spike detection requires prior readings.

### Future Improvements
1. Add configurable detection thresholds.
2. Support role-based rules or file locking.
3. Include a manual test script.



