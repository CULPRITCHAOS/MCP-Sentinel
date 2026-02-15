"""
Docker sandbox orchestrator.

Build Order: Step 9-10

Key design decisions (v0.3):
1. MCP server stdio piped via `docker run -i` subprocess (NOT Docker SDK sockets)
2. Filesystem scanning via `docker exec` (NOT docker diff — can't see tmpfs)
3. is_executable from `stat` output (NOT docker diff — has no permission data)
4. Exfil evidence from sink logs parsed host-side
5. pcap collected but not parsed (Phase 2)
"""

# TODO: Step 9 — Implement SandboxOrchestrator (start, stop, teardown)
# TODO: Step 10 — Implement _scan_tmp via docker exec find+stat+sha256sum
# TODO: Implement _monitor_resources, _get_processes, _parse_sink_captures
