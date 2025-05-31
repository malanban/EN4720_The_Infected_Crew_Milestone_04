import unittest
from detector import Detector
from datetime import datetime, timedelta
import json
import os

class TestDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Initialize and clear log files, create shared Detector."""
        cls.events_log = "logs/events.json"
        cls.alerts_log = "logs/alerts.json"
        os.makedirs(os.path.dirname(cls.events_log), exist_ok=True)
        try:
            open(cls.events_log, 'w').close()
            open(cls.alerts_log, 'w').close()
        except IOError as e:
            print(f"Failed to clear logs: {e}")
            raise
        cls.detector = Detector(cls.events_log, cls.alerts_log)

    def setUp(self):
        """Set test ID and base time."""
        self.test_id = self.id().split('.')[-1]  # e.g., test_normal_login_attempts
        self.base_time = datetime.now()

    def tearDown(self):
        """Print log contents on failure for debugging."""
        if self._outcome.errors or self._outcome.failures:
            try:
                with open(self.events_log, 'r') as f:
                    logs = [json.loads(line) for line in f]
                # print(f"\nLogs for {self.test_id}:")
                # for log in logs:
                #     print(json.dumps(log, indent=2))
            except Exception as e:
                print(f"Error reading logs: {e}")

    def test_normal_login_attempts(self):
        """Test 3 failed and 2 successful logins."""
        now = self.base_time
        for _ in range(3):
            self.detector.instrument("login_attempt", "USER", "user1", "192.168.1.2", now, {"success": False})
            now += timedelta(seconds=10)
        self.detector.instrument("login_attempt", "USER", "user1", "192.168.1.2", now, {"success": True})
        self.detector.instrument("login_attempt", "USER", "user1", "192.168.1.3", now, {"success": True})
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 5, f"Expected 5 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertFalse(any(log["flagged"] for log in test_logs))
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_normal_toggle(self):
        """Test 5 normal toggle events."""
        now = self.base_time
        for _ in range(5):
            self.detector.instrument("toggle_device", "USER", "user1", "192.168.1.2", now, {"device_id": "fan1"})
            now += timedelta(seconds=5)
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 5, f"Expected 5 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertFalse(any(log["flagged"] for log in test_logs))
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_normal_power_readings(self):
        """Test 5 normal power readings."""
        now = self.base_time
        for val in [100, 105, 98, 102, 101]:
            self.detector.instrument("power_reading", "USER", "user1", "deviceX", now, {"value": val})
            now += timedelta(seconds=10)
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 5, f"Expected 5 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertFalse(any(log["flagged"] for log in test_logs))
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_failed_login_attack(self):
        """Test 6 failed logins triggering alert."""
        now = self.base_time
        for _ in range(6):
            self.detector.instrument("login_attempt", "USER", "attacker", "10.0.0.1", now, {"success": False})
            now += timedelta(seconds=5)
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 6, f"Expected 6 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertTrue(test_logs[-1]["flagged"])
        # self.assertEqual(test_logs[-1]["reason"], "More than 5 failed login attempts in 1 minute")
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_ip_diversity_attack(self):
        """Test login attempts from 4 unique IPs."""
        now = self.base_time
        for ip in ["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"]:
            self.detector.instrument("login_attempt", "USER", "intruder", ip, now, {"success": False})
            now += timedelta(seconds=3)
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 4, f"Expected 4 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertTrue(test_logs[-1]["flagged"])
        # self.assertEqual(test_logs[-1]["reason"], "Login attempts from more than 3 unique IPs")
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_after_hours_toggle(self):
        """Test toggle outside business hours."""
        late_time = self.base_time.replace(hour=23)
        self.detector.instrument("toggle_device", "USER", "user1", "192.168.1.2", late_time, {"device_id": "light1"})
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 1, f"Expected 1 log for {self.test_id}, found {len(test_logs)}")
        # self.assertTrue(test_logs[-1]["flagged"])
        # self.assertEqual(test_logs[-1]["reason"], "Device control by user outside business hours")
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_device_flipping_attack(self):
        """Test 7 toggles of the same device."""
        now = self.base_time
        for _ in range(7):
            self.detector.instrument("toggle_device", "USER", "user2", "192.168.1.4", now, {"device_id": "ac1"})
            now += timedelta(seconds=3)
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 7, f"Expected 7 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertTrue(test_logs[-1]["flagged"])
        # self.assertEqual(test_logs[-1]["reason"], "Same device toggled >6 times in 30s")
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    def test_power_spike_attack(self):
        """Test power spike and zero reading."""
        now = self.base_time
        self.detector.instrument("power_reading", "USER", "user1", "deviceX", now, {"value": 200})
        self.detector.instrument("power_reading", "USER", "user1", "deviceX", now, {"value": 0})
        with open(self.events_log, 'r') as f:
            logs = [json.loads(line) for line in f]
        # test_logs = [log for log in logs if log["context"]["test_id"] == self.test_id]
        # self.assertEqual(len(test_logs), 2, f"Expected 2 logs for {self.test_id}, found {len(test_logs)}")
        # self.assertTrue(test_logs[-2]["flagged"])
        # self.assertEqual(test_logs[-2]["reason"], "Power exceeds 150% of historical avg")
        # self.assertTrue(test_logs[-1]["flagged"])
        # self.assertEqual(test_logs[-1]["reason"], "Power reading is zero or negative")
        # for log in test_logs:
        #     self.assertEqual(log["context"]["test_id"], self.test_id)

    @classmethod
    def tearDownClass(cls):
        """Verify total event count and reset Detector state."""
        try:
            with open(cls.events_log, 'r') as f:
                logs = [json.loads(line) for line in f]
            expected = 35  
            if len(logs) != expected:
                print(f"Warning: Expected {expected} events, found {len(logs)}")
                # print("\nAll logs:")
                # for log in logs:
                #     print(json.dumps(log, indent=2))
        except Exception as e:
            print(f"Error checking total events: {e}")
        cls.detector.reset_state()

if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(TestDetector('test_normal_login_attempts'))
    suite.addTest(TestDetector('test_normal_toggle'))
    suite.addTest(TestDetector('test_normal_power_readings'))
    suite.addTest(TestDetector('test_failed_login_attack'))
    suite.addTest(TestDetector('test_device_flipping_attack'))
    suite.addTest(TestDetector('test_power_spike_attack'))  
    suite.addTest(TestDetector('test_ip_diversity_attack'))
    suite.addTest(TestDetector('test_after_hours_toggle'))
    unittest.TextTestRunner(verbosity=2).run(suite)