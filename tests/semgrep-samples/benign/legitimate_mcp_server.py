# Benign sample: legitimate MCP server
# This should NOT trigger any rules

import json
import sys

def handle_request(request):
    """Handle MCP tool call request."""
    tool_name = request.get("tool")
    args = request.get("arguments", {})

    if tool_name == "calculate":
        a = float(args["a"])
        b = float(args["b"])
        op = args.get("operation", "add")
        if op == "add":
            return {"result": a + b}
        elif op == "subtract":
            return {"result": a - b}
        elif op == "multiply":
            return {"result": a * b}
        elif op == "divide":
            if b == 0:
                return {"error": "Division by zero"}
            return {"result": a / b}
    return {"error": f"Unknown tool: {tool_name}"}

if __name__ == "__main__":
    for line in sys.stdin:
        request = json.loads(line)
        result = handle_request(request)
        print(json.dumps(result), flush=True)
