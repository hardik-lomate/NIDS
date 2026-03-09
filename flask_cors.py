"""
flask_cors stub — adds CORS headers to all Flask responses.
Replaces the real flask-cors package when it is not installed.
"""
from flask import Flask
from functools import wraps


def CORS(app: Flask, **kwargs):
    """Attach after-request hook that injects CORS headers."""
    origins = kwargs.get("origins", "*")

    @app.after_request
    def _add_cors(response):
        response.headers["Access-Control-Allow-Origin"] = origins if isinstance(origins, str) else ", ".join(origins)
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return response

    @app.route("/<path:path>", methods=["OPTIONS"])
    def _options(path):
        from flask import Response
        return Response(status=204, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        })

    return app
