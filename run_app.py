"""
CloudVPC Studio - Application Launcher
Starts the multi-subnet VPC simulation & security suite backend and opens the web application in your default browser.
"""

import os
import sys
import webbrowser
import threading
import time

# Ensure project root is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app.server import run_server

def open_browser(port):
    time.sleep(1.2)
    url = f"http://localhost:{port}"
    print(f"[LAUNCHER] Opening {url} in your browser...")
    webbrowser.open(url)

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    # Launch browser thread
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    
    # Start HTTP server
    run_server(port)
