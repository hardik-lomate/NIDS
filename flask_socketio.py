"""
flask_socketio stub — replaces flask-socketio when not installed.

Implements real-time communication via:
  • Server-Sent Events (SSE) at /stream/<namespace>
  • Polling fallback at /api/poll
  • Event queue per namespace

The frontend index.html is patched to use polling instead of Socket.IO.
"""
import json
import queue
import threading
import time
import logging
from collections import defaultdict
from functools import wraps
from typing import Callable, Dict, Any, Optional

logger = logging.getLogger("nids.socketio_stub")

# Global event store: namespace -> list of recent events
_event_queues: Dict[str, queue.Queue] = defaultdict(lambda: queue.Queue(maxsize=500))
_recent_events: Dict[str, list] = defaultdict(list)
_recent_lock = threading.Lock()
_MAX_RECENT = 200

# Registered handlers: namespace -> event -> callable
_handlers: Dict[str, Dict[str, Callable]] = defaultdict(dict)

# Registered callbacks (on_connect, on_disconnect)
_lifecycle_handlers: Dict[str, Dict[str, Callable]] = defaultdict(dict)


def _store_event(namespace: str, event: str, data: Any):
    payload = {"event": event, "data": data, "ts": time.time()}
    # Put into queue for SSE
    try:
        _event_queues[namespace].put_nowait(payload)
    except queue.Full:
        try:
            _event_queues[namespace].get_nowait()
            _event_queues[namespace].put_nowait(payload)
        except Exception:
            pass
    # Keep a recent list for polling
    with _recent_lock:
        lst = _recent_events[namespace]
        lst.append(payload)
        if len(lst) > _MAX_RECENT:
            _recent_events[namespace] = lst[-_MAX_RECENT:]


def emit(event: str, data: Any, namespace: str = "/", **kwargs):
    """Emit an event to a namespace (callable from handlers)."""
    _store_event(namespace, event, data)


class SocketIO:
    """
    Drop-in stub for flask_socketio.SocketIO.
    Registers SSE + polling routes on the Flask app.
    """

    def __init__(self, app=None, **kwargs):
        self._app = app
        self._kwargs = kwargs
        self._routes_registered = False

        if app is not None:
            self._register_routes(app)

    # ── Decorator API ──────────────────────────────────────────────

    def on(self, event: str, namespace: str = "/"):
        """Register a Socket.IO event handler."""
        def decorator(fn: Callable):
            _handlers[namespace][event] = fn
            return fn
        return decorator

    def emit(self, event: str, data: Any, namespace: str = "/", **kwargs):
        _store_event(namespace, event, data)

    # ── App registration ───────────────────────────────────────────

    def _register_routes(self, app):
        if self._routes_registered:
            return
        self._routes_registered = True
        from flask import Response, request, jsonify

        @app.route("/stream/<path:ns>")
        def sse_stream(ns):
            """Server-Sent Events endpoint."""
            namespace = "/" + ns.lstrip("/")

            def _gen():
                last_seen = time.time() - 2
                yield "retry: 1000\n\n"
                while True:
                    with _recent_lock:
                        events = [e for e in _recent_events.get(namespace, [])
                                  if e["ts"] > last_seen]
                    for ev in events:
                        last_seen = max(last_seen, ev["ts"])
                        yield f"data: {json.dumps(ev)}\n\n"
                    if not events:
                        yield ": heartbeat\n\n"
                    time.sleep(0.5)

            return Response(_gen(), mimetype="text/event-stream",
                            headers={"Cache-Control": "no-cache",
                                     "X-Accel-Buffering": "no"})

        @app.route("/api/poll")
        def poll_events():
            """Polling fallback — returns events newer than `since` (epoch float)."""
            since = float(request.args.get("since", time.time() - 2))
            namespace = request.args.get("ns", "/nids")
            with _recent_lock:
                events = [e for e in _recent_events.get(namespace, [])
                          if e["ts"] > since]
            now = time.time()
            return jsonify({"events": events, "ts": now})

    # ── run() replaces socketio.run(app, ...) ──────────────────────

    def run(self, app, host="0.0.0.0", port=5000, **kwargs):
        """Start the Flask server (works in any thread)."""
        self._register_routes(app)
        logger.info("SocketIO stub: starting Flask server on %s:%s", host, port)
        kwargs.pop("allow_unsafe_werkzeug", None)
        try:
            from werkzeug.serving import make_server
            srv = make_server(host, port, app, threaded=True)
            logger.info("Server ready at http://%s:%s", host, port)
            srv.serve_forever()
        except Exception:
            # Fallback — only works from main thread
            app.run(host=host, port=port, threaded=True, **kwargs)
