import json
import os
from datetime import datetime, timedelta

class Detector:
    def __init__(self, events_log="logs/events.json", alerts_log="logs/alerts.json"):
        """Initialize Detector with log file paths and reset state."""
        self.events_log = events_log
        self.alerts_log = alerts_log
        os.makedirs(os.path.dirname(self.events_log), exist_ok=True)
        self.reset_state()

    def reset_state(self):
        """Clear all in-memory tracking data."""
        self.failed_login_attempts = {}
        self.toggle_events = {}
        self.power_readings = {}
        self.user_sessions = {}
        self.device_flip_counts = {}
        self.user_ip_map = {}

    def log_event(self, event, flagged=False, reason=None):
        """Log event to events.json and, if flagged, to alerts.json."""
        event_log = {
            "timestamp": event["timestamp"].isoformat(),
            "event_name": event["event_name"],
            "user_role": event["user_role"],
            "user_id": event["user_id"],
            "source_id": event["source_id"],
            "context": event["context"],
            "flagged": flagged
        }
        if flagged:
            event_log["reason"] = reason

        try:
            with open(self.events_log, "a") as f:
                json.dump(event_log, f)
                f.write("\n")
            if flagged:
                with open(self.alerts_log, "a") as f:
                    json.dump(event_log, f)
                    f.write("\n")
        except IOError as e:
            print(f"Error logging event: {e}")
            raise

    def instrument(self, event_name, user_role, user_id, source_id, timestamp, context):
        """Analyze event and log it, flagging anomalies if detected."""
        event = {
            "event_name": event_name,
            "user_role": user_role,
            "user_id": user_id,
            "source_id": source_id,
            "timestamp": timestamp,
            "context": context
        }

        flagged = False
        reason = None

        # Rule 1: Failed login attempts
        if event_name == "login_attempt":
            success = context.get("success", True)
            if not success:
                self.failed_login_attempts.setdefault(user_id, []).append(timestamp)
                self.failed_login_attempts[user_id] = [
                    t for t in self.failed_login_attempts[user_id] if timestamp - t <= timedelta(minutes=1)
                ]
                if len(self.failed_login_attempts[user_id]) > 5:
                    flagged = True
                    reason = "More than 5 failed login attempts in 1 minute"

            self.user_ip_map.setdefault(user_id, set()).add(source_id)
            if len(self.user_ip_map[user_id]) > 3:
                flagged = True
                reason = reason or "Login attempts from more than 3 unique IPs"

            if success:
                self.user_sessions.setdefault(user_id, set()).add(source_id)
                if len(self.user_sessions[user_id]) > 2:
                    flagged = True
                    reason = reason or "Concurrent sessions from more than 2 devices"

        # Rule 2: Toggle device spam
        if event_name == "toggle_device":
            self.toggle_events.setdefault(user_id, []).append(timestamp)
            self.toggle_events[user_id] = [
                t for t in self.toggle_events[user_id] if timestamp - t <= timedelta(seconds=30)
            ]
            if len(self.toggle_events[user_id]) > 10:
                flagged = True
                reason = "More than 10 toggle events in 30 seconds"

            if user_role not in ["ADMIN", "MANAGER"] and not (8 <= timestamp.hour <= 18):
                flagged = True
                reason = reason or "Device control by user outside business hours"

            device_id = context.get("device_id", "unknown")
            key = (user_id, device_id)
            self.device_flip_counts.setdefault(key, []).append(timestamp)
            self.device_flip_counts[key] = [
                t for t in self.device_flip_counts[key] if timestamp - t <= timedelta(seconds=30)
            ]
            if len(self.device_flip_counts[key]) > 6:
                flagged = True
                reason = reason or "Same device toggled >6 times in 30s"

        # Rule 3: Power reading anomalies
        if event_name == "power_reading":
            value = context.get("value", 0)
            self.power_readings.setdefault(source_id, []).append(value)
            avg_power = sum(self.power_readings[source_id]) / len(self.power_readings[source_id])
            

            if value > 1.5 * avg_power:
                flagged = True
                reason = "Power exceeds 150% of historical avg"
            elif value <= 0:
                flagged = True
                reason = "Power reading is zero or negative"

        self.log_event(event, flagged, reason)
        return flagged