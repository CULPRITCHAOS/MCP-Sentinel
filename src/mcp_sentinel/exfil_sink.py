"""
Exfiltration sink — dumb HTTP server + host-side log parser.

Build Order: Step 8

The sink itself is a minimal HTTP server that runs inside a container
and logs every request as JSON to stdout. All intelligence (canary
detection) happens host-side via parse_sink_logs().
"""

# TODO: Implement SINK_SERVER_CODE (inline Python for container)
# TODO: Implement parse_sink_logs() for host-side canary detection
