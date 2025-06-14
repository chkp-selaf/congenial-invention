import json
import time

def test_pipe():
    try:
        with open(r'\\.\pipe\ai-hook', 'w') as pipe:
            test_event = {
                "timestamp": "2025-06-14T17:50:00Z",
                "processId": 12345,
                "threadId": 67890,
                "apiType": "Test",
                "url": "https://test.example.com",
                "data": "VGVzdCBkYXRh"  # "Test data" in base64
            }
            pipe.write(json.dumps(test_event) + '\n')
            pipe.flush()
            print("Test event sent to pipe successfully!")
    except Exception as e:
        print(f"Failed to send to pipe: {e}")

if __name__ == "__main__":
    test_pipe() 