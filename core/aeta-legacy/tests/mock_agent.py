import requests
import json
import time

TELEMETRY_URL = "https://sentrymx.com/api/v1/agents/telemetry"

def generate_telemetry():
    
    return {
        "agent_id": "mock-agent-001",
        "version": "0.1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "email_received",
        "email_meta": {
            "from": "github@connormail.slmail",
            "rcpt_to": "user@domain.com",
            "source_ip": "192.0.2.123",
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "pgp_signed": False
        },
        "analysis": {
            "score": 42,
            "heuristics": ["example_heuristic"],
            "scanners": ["ip_reputation","url_analysis"],
            "latency_ms": 50
        },
        "sandbox": {
            "ran": False,
            "result": "safe"
        }
    }

def send_telemetry(data):
    # Send the fake telemetry to the defined endpoint
    headers = {'Content-Type': 'application/json'}
    response = requests.post(TELEMETRY_URL, headers=headers, data=json.dumps(data))
    print(f"Sent telemetry, got response: {response.status_code}")

if __name__ == "__main__":
    fake_data = generate_fake_telemetry()
    send_telemetry(fake_data)