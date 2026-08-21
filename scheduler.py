"""Dedicated production scheduler. Run as a separate worker process."""
from app import start_scheduler

if __name__ == "__main__":
    scheduler = start_scheduler()
    print("Holy Bethel scheduler started.")
    try:
        import signal, time
        signal.pause()
    except (AttributeError, KeyboardInterrupt):
        while True:
            time.sleep(3600)
