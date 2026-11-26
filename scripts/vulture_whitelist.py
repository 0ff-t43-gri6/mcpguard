"""Names vulture reports as unused but which are used by frameworks or kept on purpose.

Checked by `python scripts/check.py`; add to this file only with a reason.
"""

# http.server calls these by name.
_.do_GET
_.do_POST
_.log_message
_.server_version
_.sys_version
_.daemon_threads

# Dataclass fields written to the state snapshot and shown in the dashboard.
_.restarts
_.since
_.created

# Alert delivery counters, kept for debugging and future metrics.
_.sent
_.failed
_.request_queue_size  # read by socketserver
