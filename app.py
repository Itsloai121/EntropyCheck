import os
import sys
import shutil
import subprocess
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, jsonify, render_template, request
from zynx_password_checker import (
    MAX_PASSWORD_LENGTH,
    ONLINE_GUESSES_PER_SECOND,
    OFFLINE_FAST_HASH_GUESSES_PER_SECOND,
    analyze_password,
    estimate_crack_time
)

app = Flask(__name__)

# Limit incoming request size.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# Project paths
BASE_DIR = Path(__file__).resolve().parent
TUI_SCRIPT = BASE_DIR / "zynx_password_checker.py"

# Main website page.
@app.route("/")
def index():
    return render_template("index.html")

# Password analysis API.
@app.route("/api/analyze", methods=["POST"])
def analyze():
    # Read JSON sent by the website.
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid request data."
        }), 400

    password = data.get("password")

    # Validate input.
    if not isinstance(password, str):
        return jsonify({
            "error": "Password must be a string."
        }), 400

    if len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({
            "error": f"Maximum password length is {MAX_PASSWORD_LENGTH} characters."
        }), 400

    try:
        # Run your EXISTING password analysis engine.
        report = analyze_password(password)

        # Calculate estimated cracking times.
        online_time = estimate_crack_time(
            report.entropy_bits,
            ONLINE_GUESSES_PER_SECOND
        )
        offline_time = estimate_crack_time(
            report.entropy_bits,
            OFFLINE_FAST_HASH_GUESSES_PER_SECOND
        )

        # Return results to JavaScript.
        results = {
            "length": report.length,
            "score": report.score,
            "grade": report.grade,
            "entropy_bits": round(
                report.entropy_bits, 2
            ),
            "pool_size": report.pool_size,
            "uses_unicode": report.uses_unicode,
            "character_classes": report.character_classes,
            "common_match": report.common_match,
            "pattern_warnings": list(
                report.pattern_warnings
            ),
            "recommendations": list(
                report.recommendations
            ),
            "crack_time": {
                "online": online_time,
                "offline": offline_time
            }
        }
        return jsonify(results)

    except (TypeError, ValueError) as error:
        return jsonify({
            "error": str(error)
        }), 400
    except Exception:
        # Avoid exposing internal errors or password data.
        app.logger.exception("Password analysis failed.")
        return jsonify({
            "error": "An internal analysis error occurred."
        }), 500

@app.route("/api/launch-tui", methods=["POST"])
def launch_tui():
    # Only allow requests from the local computer.
    try:
        if not ipaddress.ip_address(request.remote_addr).is_loopback:
            return jsonify({
                "success": False,
                "error": "Local access only."
            }), 403
    except (ValueError, TypeError):
        return jsonify({
            "success": False,
            "error": "Invalid client address."
        }), 403

    # Reject cross-origin browser requests.
    origin = request.headers.get("Origin")
    if origin:
        parsed = urlsplit(origin)
        if parsed.netloc.lower() != request.host.lower():
            return jsonify({
                "success": False,
                "error": "Cross-origin request rejected."
            }), 403

    # TUI launching requires Windows PowerShell.
    if os.name != "nt":
        return jsonify({
            "success": False,
            "error": "Automatic TUI launching is supported on Windows. Run the TUI from your terminal instead."
        }), 501

    # Verify the Python application exists.
    if not TUI_SCRIPT.is_file():
        return jsonify({
            "success": False,
            "error": "TUI Python file was not found."
        }), 404

    # Find PowerShell.
    powershell = (
        shutil.which("pwsh.exe")
        or shutil.which("powershell.exe")
    )

    if not powershell:
        return jsonify({
            "success": False,
            "error": "PowerShell was not found."
        }), 500

    # Use the same Python interpreter running Flask.
    python_executable = Path(sys.executable)

    if python_executable.name.lower() == "pythonw.exe":
        python_executable = python_executable.with_name("python.exe")

    # Safely quote paths for PowerShell.
    def ps_quote(value):
        return "'" + str(value).replace("'", "''") + "'"

    command = (
        f"& {ps_quote(python_executable)} "
        f"{ps_quote(TUI_SCRIPT)} --tui"
    )

    try:
        # Open a separate interactive PowerShell window.
        subprocess.Popen(
            [
                powershell,
                "-NoLogo",
                "-NoExit",
                "-Command",
                command
            ],
            cwd=str(BASE_DIR),
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )

        return jsonify({
            "success": True,
            "message": "TUI launched in a new PowerShell window."
        }), 202

    except OSError:
        app.logger.exception("TUI launch failed.")

        return jsonify({
            "success": False,
            "error": "Unable to launch the PowerShell window."
        }), 500

# Handle oversized requests.
@app.errorhandler(413)
def request_too_large(error):
    return jsonify({
        "error": "Request is too large."
    }), 413

# Start the local web server.
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )