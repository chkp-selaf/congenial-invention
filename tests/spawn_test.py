import subprocess
import time
import sys

def main():
    print("Starting child process spawn test...")
    
    # Spawn a few child processes to test monitoring
    children = []
    
    for i in range(3):
        print(f"Spawning child process {i+1}...")
        # Use ping as a simple child process that will run for a few seconds
        child = subprocess.Popen([
            "ping", "127.0.0.1", "-n", "5"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        time.sleep(2)  # Stagger the spawning
    
    print("All child processes spawned. Waiting for them to complete...")
    
    # Wait for all children to complete
    for i, child in enumerate(children):
        print(f"Waiting for child {i+1} (PID: {child.pid})...")
        child.wait()
        print(f"Child {i+1} completed with return code: {child.returncode}")
    
    print("Child process spawn test completed.")
    time.sleep(5)  # Give time for monitoring to see the processes

if __name__ == "__main__":
    main() 