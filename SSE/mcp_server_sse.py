from fastapi import FastAPI, Request
import subprocess
import json
import logging
import os
from datetime import datetime

app = FastAPI()
logging.basicConfig(
    filename='logs/mcp_server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(message)s'
)

@app.post("/messages")
async def messages(request: Request):
    try:
        data = await request.json()
        logging.info(f"Received request data: {json.dumps(data)}")
    except Exception as e:
        logging.error(f"Failed to parse JSON request: {str(e)}")
        return {"status": "error", "message": f"Invalid JSON request: {str(e)}"}

    if data.get("method") != "call_tool" or data["params"]["tool_name"] != "nuclei_scan":
        error_msg = "Invalid request: method must be 'call_tool' and tool_name must be 'nuclei_scan'"
        logging.error(error_msg)
        return {"status": "error", "message": error_msg}

    url = data["params"]["args"]["urls"][0]
    templates = data["params"]["args"]["template_paths"]
    logging.info(f"Processing nuclei_scan with URLs: {url}, Templates: {templates}")

    try:
        # Kiểm tra template tồn tại
        for template in templates:
            if not os.path.exists(template):
                error_msg = f"Template file not found: {template}"
                logging.error(error_msg)
                return {"status": "error", "message": error_msg}

        # Kiểm tra URL hợp lệ
        if not url.startswith(("http://", "https://")):
            error_msg = f"Invalid URL: {url}"
            logging.error(error_msg)
            return {"status": "error", "message": error_msg}

        # Kiểm tra Nuclei binary
        if not os.path.exists("/usr/local/bin/nuclei"):
            error_msg = "Nuclei binary not found in /usr/local/bin/nuclei"
            logging.error(error_msg)
            return {"status": "error", "message": error_msg}

        # Chạy Nuclei với tùy chọn -no-interactsh và timeout
        cmd = ["nuclei", "-u", url, "-t", ",".join(templates), "-jsonl", "-silent", "-no-color", "-no-interactsh", "-rate-limit", "1"]
        logging.info(f"Running Nuclei command: {' '.join(cmd)}")
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, error = process.communicate(timeout=150)  # Timeout 150 giây cho Nuclei
            logging.info(f"Nuclei output: {output[:500]}")
            if error:
                logging.error(f"Nuclei stderr: {error}")
        except subprocess.TimeoutExpired:
            process.kill()
            error_msg = "Nuclei scan timed out after 150 seconds"
            logging.error(error_msg)
            return {"status": "error", "message": error_msg}
        except subprocess.SubprocessError as e:
            error_msg = f"Failed to run Nuclei: {str(e)}"
            logging.error(error_msg)
            return {"status": "error", "message": error_msg}

        if process.returncode != 0:
            error_msg = error if error else "Nuclei exited with non-zero status"
            logging.error(f"Error scanning {url}: {error_msg}")
            return {"status": "error", "message": error_msg}

        if not output:
            error_msg = "Nuclei returned no output"
            logging.error(error_msg)
            return {"status": "error", "message": error_msg}

        # Kiểm tra định dạng đầu ra của Nuclei
        try:
            for line in output.splitlines():
                if line.strip():  # Bỏ qua các dòng trống
                    json.loads(line)
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSONL output from Nuclei: {str(e)}"
            logging.error(error_msg)
            return {"status": "error", "message": error_msg}

        if not os.path.exists("logs"):
            os.makedirs("logs")
            logging.info("Created logs directory")
        with open("logs/scan_results.json", "w") as f:
            f.write(output)
        logging.info(f"Scan completed for {url} at {datetime.now()}")
        return {"status": "success"}
    except FileNotFoundError as e:
        error_msg = "Nuclei binary not found. Ensure Nuclei is installed in the container."
        logging.error(error_msg)
        return {"status": "error", "message": error_msg}
    except Exception as e:
        error_msg = str(e)
        logging.error(f"Exception during scan: {error_msg}")
        return {"status": "error", "message": error_msg}