"""Notification adapter for the local demo environment.

Email delivery can be added later through environment-based SMTP settings.
For now alerts are deliberately visible in the backend console.
"""


def notify(subject: str, message: str) -> None:
    print(f"[SessionSentinel alert] {subject}: {message}", flush=True)
