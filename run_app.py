"""
CloudVPC Studio - Application Launcher
Supports both standalone local Python server and Streamlit Cloud execution.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def is_running_in_streamlit():
    try:
        import streamlit as st
        return True
    except Exception:
        return False

# If Streamlit is running this file, hand over to streamlit_app directly
try:
    from streamlit.runtime.scriptrunner import get_script_run_ctx
    if get_script_run_ctx() is not None:
        import streamlit_app
except Exception:
    pass

def open_browser(port):
    import time
    import webbrowser
    time.sleep(1.2)
    url = f"http://localhost:{port}"
    print(f"[LAUNCHER] Opening {url} in your browser...")
    webbrowser.open(url)

if __name__ == "__main__":
    # Check if executed via streamlit run run_app.py
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        in_streamlit = get_script_run_ctx() is not None
    except Exception:
        in_streamlit = False

    if in_streamlit:
        import streamlit_app
    else:
        import threading
        try:
            from app.server import run_server
        except ImportError:
            # Fallback if app directory is not present
            import streamlit_app
            sys.exit(0)

        port = 8000
        if len(sys.argv) > 1:
            try:
                port = int(sys.argv[1])
            except ValueError:
                pass

        threading.Thread(target=open_browser, args=(port,), daemon=True).start()
        run_server(port)
