#!/usr/bin/env python3
"""Minimal MCP stdio client for testing `fnox mcp`.

usage: mcp_client.py FNOX_BIN ELICIT PAGE CALLS

ELICIT is "url" to declare URL-mode elicitation or "none" to declare none.
PAGE says what to do on the page an elicitation links to: "save:VALUE",
"decline", or "none". CALLS is a JSON list of [tool, arguments] pairs, or the
string "list" to list tools. A call named "$" runs its arguments as a command
between tool calls, in the same session, and prints {"ran": <exit code>}.

Prints one JSON line per call result, then {"page": <status or null>}.
"""

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

fnox_bin, elicit, page_action, calls = sys.argv[1:5]

proc = subprocess.Popen(
    [fnox_bin, "mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True,
)
# Fail fast instead of waiting out request_secret's own timeout
watchdog = threading.Timer(60, proc.kill)
watchdog.daemon = True
watchdog.start()
next_id = 0
page_status = []
page_threads = []


def send(message):
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def request(method, params):
    global next_id
    next_id += 1
    send({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params})
    return next_id


def fill_page(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=30) as response:
        assert response.status == 200, response.status
    if page_action == "none":
        return
    if page_action == "decline":
        fields = {"action": "decline"}
    else:
        fields = {"value": page_action.split(":", 1)[1], "action": "save"}
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url))
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, headers={"Origin": origin})
    try:
        with opener.open(req, timeout=60) as response:
            page_status.append(response.status)
    except urllib.error.HTTPError as error:
        page_status.append(error.code)


def wait_for(request_id):
    for line in proc.stdout:
        message = json.loads(line)
        if message.get("method") == "elicitation/create":
            params = message["params"]
            assert params["mode"] == "url", params
            send({"jsonrpc": "2.0", "id": message["id"], "result": {"action": "accept"}})
            thread = threading.Thread(target=fill_page, args=(params["url"],))
            thread.start()
            page_threads.append(thread)
        elif message.get("id") == request_id:
            return message
    raise SystemExit("fnox mcp exited early")


capabilities = {"elicitation": {"url": {}}} if elicit == "url" else {}
wait_for(
    request(
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": capabilities,
            "clientInfo": {"name": "fnox-test", "version": "0"},
        },
    )
)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

if calls == "list":
    result = wait_for(request("tools/list", {}))
    print(json.dumps([tool["name"] for tool in result["result"]["tools"]]))
else:
    for name, arguments in json.loads(calls):
        if name == "$":
            ran = subprocess.run(arguments, stdout=subprocess.DEVNULL)
            print(json.dumps({"ran": ran.returncode}))
            continue
        response = wait_for(request("tools/call", {"name": name, "arguments": arguments}))
        print(json.dumps(response.get("result") or response.get("error")))

for thread in page_threads:
    thread.join()
print(json.dumps({"page": page_status[0] if page_status else None}))
proc.stdin.close()
proc.wait(timeout=10)
