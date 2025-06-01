from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv
import logging
import re
import time

# Cấu hình logging
logging.basicConfig(
    filename='logs/web_client.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s:%(message)s'
)

load_dotenv()
app = FastAPI()
templates = Jinja2Templates(directory="templates")

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"
SSE_PORT = int(os.getenv("SSE_PORT", 8001))
SSE_HOST = os.getenv("SSE_HOST", "mcp-server")

# SSE Transport Simulation (stream messages)
async def sse_generator():
    try:
        if not os.path.exists("logs/scan_results.json"):
            logging.error("Scan results file not found at logs/scan_results.json")
            yield f"data: {json.dumps({'status': 'error', 'message': 'Scan results file not found'})}\n\n"
            return
        with open("logs/scan_results.json", "r") as f:
            for line in f:
                if line.strip():
                    try:
                        json.loads(line)  # Kiểm tra JSON hợp lệ trước khi gửi
                        yield f"data: {line}\n\n"
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping invalid JSON line in SSE: {line[:100]}")
                        continue
    except FileNotFoundError:
        logging.error("Scan results file not found during SSE streaming")
        yield f"data: {json.dumps({'status': 'error', 'message': 'Scan results file not found'})}\n\n"
    except Exception as e:
        logging.error(f"Error during SSE streaming: {str(e)}")
        yield f"data: {json.dumps({'status': 'error', 'message': str(e)})}\n\n"

@app.get("/sse")
async def sse_endpoint():
    return StreamingResponse(sse_generator(), media_type="text/event-stream")

@app.post("/messages")
async def messages(request: Request):
    try:
        data = await request.json()
        logging.info(f"Received /messages request: {json.dumps(data)}")
    except Exception as e:
        logging.error(f"Failed to parse JSON request in /messages: {str(e)}")
        return {"status": "error", "message": f"Invalid JSON request: {str(e)}"}

    if data.get("method") != "call_tool" or data["params"]["tool_name"] != "nuclei_scan":
        error_msg = "Invalid request: method must be 'call_tool' and tool_name must be 'nuclei_scan'"
        logging.error(error_msg)
        return {"status": "error", "message": error_msg}

    url = data["params"]["args"]["urls"][0]
    templates = data["params"]["args"]["template_paths"]
    try:
        start_time = datetime.now()
        if not os.path.exists("logs"):
            os.makedirs("logs")
            logging.info("Created logs directory")
        with open("logs/scan_results.json", "w") as f:
            f.write(json.dumps({"url": url, "templates": templates, "status": "scanning"}))
        logging.info(f"Initialized scan for URL: {url}, Templates: {templates}")
        return {"status": "received"}
    except Exception as e:
        logging.error(f"Failed to process /messages request: {str(e)}")
        return {"status": "error", "message": f"Failed to process request: {str(e)}"}

@app.get("/")
async def index(request: Request):
    try:
        templates_list = os.listdir("scanner/templates")
        logging.info(f"Loaded templates list: {templates_list}")
        return templates.TemplateResponse("index.html", {"request": request, "templates": templates_list})
    except FileNotFoundError as e:
        logging.error(f"Failed to load templates directory: {str(e)}")
        return templates.TemplateResponse("index.html", {"request": request, "templates": [], "error_message": "Templates directory not found"})
    except Exception as e:
        logging.error(f"Unexpected error in / endpoint: {str(e)}")
        return templates.TemplateResponse("index.html", {"request": request, "templates": [], "error_message": str(e)})

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request):
    scan_results = []
    if os.path.exists('logs/scan_results.json'):
        try:
            with open('logs/scan_results.json', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            scan_results.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            logging.warning(f"Skipping invalid JSON line in scan_results.json: {line[:100]}")
                            continue
        except Exception as e:
            scan_results = []
            logging.error(f"Error reading scan_results.json: {str(e)}")

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for result in scan_results:
        severity = result.get('severity', 'low').lower()
        if severity in summary:
            summary[severity] += 1
        else:
            summary['low'] += 1

    scan_history = []
    duration = 0
    analysis = "No analysis available."
    if os.path.exists('logs/scan_history.json'):
        try:
            with open('logs/scan_history.json', 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
            if scan_history:
                duration = scan_history[-1].get('duration', 0)
                analysis = scan_history[-1].get('analysis', "No analysis available.")
        except Exception as e:
            logging.error(f"Error reading scan_history.json: {str(e)}")

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "results": scan_results,
            "summary": summary,
            "duration": duration,
            "analysis": analysis,
            "error_message": "No vulnerabilities found. Please run a scan first." if not scan_results else None
        }
    )

@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    scan_history = []
    if os.path.exists('logs/scan_history.json'):
        try:
            with open('logs/scan_history.json', 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
        except Exception as e:
            scan_history = []
            logging.error(f"Error reading scan_history.json: {str(e)}")
    return templates.TemplateResponse("history.html", {"request": request, "scan_history": scan_history})

@app.get("/history/{results_file}", response_class=HTMLResponse)
async def view_history_results(request: Request, results_file: str):
    scan_results = []
    results_path = f"logs/{results_file}"
    if os.path.exists(results_path):
        try:
            with open(results_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            scan_results.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            logging.warning(f"Skipping invalid JSON line in {results_path}: {line[:100]}")
                            continue
        except Exception as e:
            scan_results = []
            logging.error(f"Error reading {results_path}: {str(e)}")

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for result in scan_results:
        severity = result.get('severity', 'low').lower()
        if severity in summary:
            summary[severity] += 1
        else:
            summary['low'] += 1

    scan_history = []
    duration = 0
    analysis = "No analysis available."
    if os.path.exists('logs/scan_history.json'):
        try:
            with open('logs/scan_history.json', 'r', encoding='utf-8') as f:
                scan_history = json.load(f)
            for entry in scan_history:
                if entry.get('results_file') == results_file:
                    duration = entry.get('duration', 0)
                    analysis = entry.get('analysis', "No analysis available.")
                    break
        except Exception as e:
            logging.error(f"Error reading scan_history.json: {str(e)}")

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "results": scan_results,
            "summary": summary,
            "duration": duration,
            "analysis": analysis,
            "error_message": "No vulnerabilities found in this scan session." if not scan_results else None
        }
    )

@app.post("/scan")
async def scan(request: Request):
    def render_error_template(request, error_message):
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "error_message": error_message,
                "results": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "duration": 0,
                "analysis": ""
            }
        )

    try:
        form = await request.form()
        scan_type = form.get("scan_type")
        if scan_type is None:
            error_message = "Scan type is missing in the form data"
            logging.error(error_message)
            return render_error_template(request, error_message)
        scan_type = scan_type.lower()  # Chuyển scan_type về chữ thường để tránh lỗi
        start_time = datetime.now()
        logging.info(f"Received /scan request with scan_type: {scan_type}")
    except Exception as e:
        logging.error(f"Failed to parse form data in /scan: {str(e)}")
        return render_error_template(request, f"Failed to parse form data: {str(e)}")
    
    history_entry = {
        "timestamp": start_time.isoformat(),
        "url": form.get("url", ""),
        "template": form.get("template", ""),
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "duration": 0,
        "analysis": ""
    }

    if scan_type == "manual":
        url = form.get("url", "").strip()
        template = form.get("template", "").strip()
        if not url or not url.startswith(("http://", "https://")):
            error_message = "Invalid URL: URL must start with http:// or https://"
            logging.error(error_message)
            history_entry["analysis"] = error_message
            await save_to_history(history_entry, start_time)
            return render_error_template(request, error_message)
        if not template or not template.endswith(".yaml"):
            error_message = "Invalid template: Template must be a .yaml file"
            logging.error(error_message)
            history_entry["analysis"] = error_message
            await save_to_history(history_entry, start_time)
            return render_error_template(request, error_message)
        url = re.sub(r'[^a-zA-Z0-9:/?=&._-]', '', url)
        template = re.sub(r'[^a-zA-Z0-9_\-\.]', '', template)
        template_path = f"scanner/templates/{template}"
        if not os.path.exists(template_path):
            error_message = f"Template file not found: {template_path}"
            logging.error(error_message)
            history_entry["analysis"] = error_message
            await save_to_history(history_entry, start_time)
            return render_error_template(request, error_message)

        data = {
            "jsonrpc": "2.0",
            "method": "call_tool",
            "params": {
                "tool_name": "nuclei_scan",
                "args": {
                    "urls": [url],
                    "template_paths": [template_path]
                }
            },
            "id": 1
        }
        retries = 3
        for attempt in range(retries):
            try:
                logging.info(f"Attempt {attempt + 1}/{retries}: Calling /messages with data: {json.dumps(data)}")
                test_response = requests.get(f"http://{SSE_HOST}:{SSE_PORT}/", timeout=5)
                logging.info(f"Test connection to mcp-server: status code: {test_response.status_code}, headers: {test_response.headers}, content: {test_response.text[:500]}")
                response = requests.post(f"http://{SSE_HOST}:{SSE_PORT}/messages", json=data, timeout=180)
                logging.info(f"Received response with status code: {response.status_code}, headers: {response.headers}, content: {response.text[:500]}")
                response.raise_for_status()
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' not in content_type:
                    error_message = f"Expected JSON response, but received: {content_type}, content: {response.text[:500]}"
                    logging.error(error_message)
                    history_entry["analysis"] = error_message
                    await save_to_history(history_entry, start_time)
                    return render_error_template(request, error_message)
                response_data = response.json()
                logging.info(f"Response data: {response_data}")
                if response_data.get("status") != "success":
                    error_message = response_data.get("message", "An unknown error occurred during scan.")
                    history_entry["analysis"] = error_message
                    await save_to_history(history_entry, start_time)
                    return render_error_template(request, error_message)
                results = []
                summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                if not os.path.exists("logs/scan_results.json"):
                    error_message = "Scan results file not found after successful scan"
                    logging.error(error_message)
                    history_entry["analysis"] = error_message
                    await save_to_history(history_entry, start_time)
                    return render_error_template(request, error_message)
                with open("logs/scan_results.json", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                result = json.loads(line)
                                if result.get("status") == "scanning":
                                    continue
                                results.append(result)
                                severity = result.get("severity", "low").lower()
                                if severity == "critical":
                                    summary["critical"] += 1
                                elif severity == "high":
                                    summary["high"] += 1
                                elif severity == "medium":
                                    summary["medium"] += 1
                                else:
                                    summary["low"] += 1
                            except json.JSONDecodeError as e:
                                logging.warning(f"Skipping invalid JSON line in scan_results.json: {line[:100]}")
                                continue
                history_entry["summary"] = summary
                await save_to_history(history_entry, start_time)
                logging.info(f"Manual scan completed for URL: {url}, Results: {len(results)}")
                return templates.TemplateResponse("results.html", {
                    "request": request,
                    "results": results,
                    "summary": summary,
                    "duration": 0,
                    "analysis": ""
                })
            except requests.Timeout:
                if attempt == retries - 1:
                    error_message = "Request to MCP Server timed out after multiple attempts. Please check if mcp-server is running and accessible."
                    logging.error(error_message)
                    history_entry["analysis"] = error_message
                    await save_to_history(history_entry, start_time)
                    return render_error_template(request, error_message)
                logging.warning("Request timed out, retrying...")
                time.sleep(5)
            except requests.ConnectionError as e:
                error_message = f"Failed to connect to MCP Server: {str(e)}"
                logging.error(error_message)
                history_entry["analysis"] = error_message
                await save_to_history(history_entry, start_time)
                return render_error_template(request, error_message)
            except requests.RequestException as e:
                error_message = f"Failed to communicate with MCP Server: {str(e)}"
                logging.error(error_message)
                history_entry["analysis"] = error_message
                await save_to_history(history_entry, start_time)
                return render_error_template(request, error_message)
            except ValueError as e:
                error_message = f"Failed to parse response as JSON: {str(e)}"
                logging.error(error_message)
                history_entry["analysis"] = error_message
                await save_to_history(history_entry, start_time)
                return render_error_template(request, error_message)
            except Exception as e:
                error_message = f"Unexpected error: {str(e)}"
                logging.error(error_message)
                history_entry["analysis"] = error_message
                await save_to_history(history_entry, start_time)
                return render_error_template(request, error_message)
    elif scan_type == "deepseek":
        deepseek_input = form.get("deepseek_input", "").strip()
        if not deepseek_input:
            error_message = "DeepSeek command cannot be empty"
            logging.error(error_message)
            history_entry["analysis"] = error_message
            await save_to_history(history_entry, start_time)
            return render_error_template(request, error_message)
        # ... (logic deepseek giữ nguyên như cũ) ...
    else:
        error_message = f"Invalid scan type: {scan_type}. Expected 'manual' or 'deepseek'"
        logging.error(error_message)
        history_entry["analysis"] = error_message
        await save_to_history(history_entry, start_time)
        return render_error_template(request, error_message)

async def save_to_history(history_entry, start_time):
    try:
        end_time = datetime.now()
        history_entry["duration"] = (end_time - start_time).total_seconds()
        if not os.path.exists("logs"):
            os.makedirs("logs")
            logging.info("Created logs directory for saving history")
        if not os.path.exists("logs/scan_history.json"):
            with open("logs/scan_history.json", "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            logging.info("Initialized empty scan history file")
        try:
            with open("logs/scan_history.json", "r", encoding="utf-8") as f:
                history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.warning(f"Error loading scan history, initializing empty history: {str(e)}")
            history = []
        history.append(history_entry)
        with open("logs/scan_history.json", "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
        logging.info(f"Saved scan history entry at {history_entry['timestamp']}")
    except Exception as e:
        logging.error(f"Failed to save scan history: {str(e)}")