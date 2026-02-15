"""
Docker sandbox orchestrator.

Build Order: Step 9-10

Key design decisions (v0.3):
1. MCP server stdio piped via `docker run -i` subprocess (NOT Docker SDK sockets)
2. Filesystem scanning via `docker exec` (NOT docker diff -- can't see tmpfs)
3. is_executable from `stat` output (NOT docker diff -- has no permission data)
4. Exfil evidence from sink logs parsed host-side
5. pcap collected but not parsed (Phase 2)
"""

import asyncio
import logging
import os
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import docker

from mcp_sentinel.exfil_sink import SINK_PORT, SINK_SERVER_CODE, parse_sink_logs
from mcp_sentinel.models import FilesystemEntry, ResourceSnapshot

logger = logging.getLogger(__name__)

# Canary credentials (injected as env vars into server container)
CANARY_ENV_VARS = {
    "AWS_ACCESS_KEY_ID": "AKIASENTINEL" + os.urandom(8).hex().upper(),
    "AWS_SECRET_ACCESS_KEY": "sentinel/" + os.urandom(24).hex(),
    "GITHUB_TOKEN": "ghp_SENTINEL" + os.urandom(16).hex(),
    "DATABASE_URL": "postgresql://sentinel:canary@fakedb:5432/trap",
    "OPENAI_API_KEY": "sk-sentinel-" + os.urandom(24).hex(),
    "ANTHROPIC_API_KEY": "sk-ant-sentinel-" + os.urandom(24).hex(),
    "STRIPE_SECRET_KEY": "sk_test_sentinel" + os.urandom(16).hex(),
    "SLACK_TOKEN": "xoxb-sentinel-" + os.urandom(16).hex(),
}

# Domains that resolve to the exfil sink during testing
TRAPPED_DOMAINS = [
    "evil-exfil.example.com",
    "evil.com",
    "attacker.io",
    "c2-server.net",
]

SINK_HOSTNAME = "exfil-sink"


class SandboxOrchestrator:
    """
    Full sandbox lifecycle:
    1. Create isolated Docker network
    2. Start exfil sink
    3. Start observer sidecar (pcap capture, Phase 2 parsing)
    4. Launch MCP server via subprocess (docker run -i)
    5. Return subprocess stdin/stdout for MCP client to use
    6. After tests: scan /tmp, parse sink logs, collect resource stats
    7. Tear down
    """

    def __init__(
        self,
        image: str,
        server_args: list[str] | None = None,
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
    ):
        self.image = image
        self.server_args = server_args or []
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit

        self.docker_client = docker.from_env()
        self.network = None
        self.sink_container = None
        self.observer_container = None
        self.server_process: asyncio.subprocess.Process | None = None
        self.telemetry_dir = Path(tempfile.mkdtemp(prefix="sentinel_"))
        self.resource_snapshots: list[ResourceSnapshot] = []
        self._resource_task: asyncio.Task | None = None
        self._network_name: str = ""
        self._server_container_name: str = ""
        self._scan_errors: list[str] = []
        self._host_mode: bool = False
        self._sink_ip: str = "127.0.0.1"

    async def start(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Bring up sandbox and return (reader, writer) for MCP stdio.

        Returns:
            (stdout_reader, stdin_writer) connected to the MCP server's
            stdio inside the hardened container.
        """
        run_id = os.urandom(4).hex()
        self._network_name = f"sentinel_net_{run_id}"
        self._server_container_name = f"sentinel_mcp_{run_id}"

        # 1. Create isolated network (internal = no internet)
        # Falls back to host networking if bridge creation fails (e.g., in CI
        # containers where kernel lacks bridge/iptables support).
        try:
            self.network = self.docker_client.networks.create(
                self._network_name,
                driver="bridge",
                internal=True,
            )
            self._host_mode = False
        except docker.errors.APIError as e:
            logger.warning(
                "Bridge network creation failed (%s), falling back to host mode", e
            )
            self._host_mode = True
            self._network_name = "host"

        # 2. Start exfil sink
        sink_name = f"sentinel_sink_{run_id}"
        sink_kwargs = {
            "detach": True,
            "name": sink_name,
            "labels": {"sentinel.role": "exfil-sink"},
        }
        if self._host_mode:
            sink_kwargs["network_mode"] = "host"
        else:
            sink_kwargs["network"] = self._network_name

        self.sink_container = self.docker_client.containers.run(
            self.image,  # Use same image (has Python) for sink
            command=["python", "-u", "-c", SINK_SERVER_CODE],
            **sink_kwargs,
        )

        # Wait for sink to be READY (deterministic polling, not sleep)
        await self._wait_for_sink_ready(sink_name)

        # Get sink IP
        if self._host_mode:
            self._sink_ip = "127.0.0.1"
        else:
            self.sink_container.reload()
            self._sink_ip = self._get_container_ip(self.sink_container)

        # 3. Start observer sidecar (pcap -- Phase 2 parsing)
        # Skip observer in host mode (tcpdump needs NET_RAW which may not be
        # available, and pcap parsing is deferred to Phase 2 anyway)
        if not self._host_mode:
            observer_name = f"sentinel_observer_{run_id}"
            try:
                self.observer_container = self.docker_client.containers.run(
                    "nicolaka/netshoot:latest",
                    command=[
                        "tcpdump",
                        "-i",
                        "any",
                        "-nn",
                        "-l",
                        "-w",
                        "/telemetry/capture.pcap",
                        "not",
                        "port",
                        "22",
                    ],
                    detach=True,
                    network=self._network_name,
                    cap_add=["NET_RAW", "NET_ADMIN"],
                    volumes={
                        str(self.telemetry_dir): {
                            "bind": "/telemetry",
                            "mode": "rw",
                        }
                    },
                    labels={"sentinel.role": "observer"},
                )
            except docker.errors.APIError:
                # Observer is non-critical (pcap parsing is Phase 2)
                logger.warning("Observer sidecar failed to start (non-critical)")

        # 4. Build extra_hosts mapping (trapped domains -> sink)
        extra_hosts = [
            f"{domain}:{self._sink_ip}" for domain in TRAPPED_DOMAINS
        ]

        # 5. Launch MCP server via subprocess docker run -i
        docker_cmd = [
            "docker",
            "run",
            "-i",  # Interactive (stdin open)
            "--rm",  # Cleanup on exit
            f"--name={self._server_container_name}",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            "--pids-limit=100",
            "--read-only",
            "--tmpfs=/tmp:rw,nosuid,size=64M",
            "--security-opt=no-new-privileges:true",
            "--cap-drop=ALL",
        ]

        if self._host_mode:
            docker_cmd.append("--network=host")
        else:
            docker_cmd.append(f"--network={self._network_name}")

        # Inject canary env vars
        for key, val in CANARY_ENV_VARS.items():
            docker_cmd.extend(["-e", f"{key}={val}"])

        # Inject hosts mapping
        for mapping in extra_hosts:
            docker_cmd.extend(["--add-host", mapping])

        # Image and optional args
        docker_cmd.append(self.image)
        docker_cmd.extend(self.server_args)

        self.server_process = await asyncio.create_subprocess_exec(
            *docker_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Give server a moment to start
        await asyncio.sleep(2)

        # 6. Start resource monitoring
        self._resource_task = asyncio.create_task(self._monitor_resources())

        return self.server_process.stdout, self.server_process.stdin

    async def _wait_for_sink_ready(self, sink_name: str, timeout: float = 15):
        """
        Poll until the exfil sink is actually listening on SINK_PORT.

        Anti-flake: The evil server may exfil immediately on first tool call.
        If the sink isn't ready, those captures are lost → false negative for
        MUST PASS #3/#4.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                self.sink_container.reload()
                status = self.sink_container.status
                if status != "running":
                    await asyncio.sleep(0.3)
                    continue

                # Try connecting to the sink port to verify it's listening
                if self._host_mode:
                    # On host mode, check localhost directly
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(("127.0.0.1", SINK_PORT))
                    sock.close()
                    if result == 0:
                        return
                else:
                    # On bridge mode, use docker exec to check
                    check = self.docker_client.containers.get(sink_name)
                    exit_code, _ = check.exec_run(
                        ["python", "-c",
                         f"import socket; s=socket.socket(); "
                         f"s.settimeout(1); s.connect(('127.0.0.1',{SINK_PORT})); "
                         f"s.close(); print('ok')"],
                        demux=False,
                    )
                    if exit_code == 0:
                        return
            except Exception:
                pass
            await asyncio.sleep(0.5)

        logger.warning(
            "Sink readiness check timed out after %.0fs — proceeding anyway",
            timeout,
        )

    async def stop(self) -> dict:
        """
        Tear down sandbox and return all telemetry.

        Returns dict with:
        - filesystem_entries: list[FilesystemEntry]
        - exfil_captures: list[dict] (with canary analysis)
        - resource_snapshots: list[ResourceSnapshot]
        - processes: list[str]
        - pcap_path: str
        - scan_errors: list[str] (any errors during /tmp scan)
        """
        # Stop resource monitor
        if self._resource_task:
            self._resource_task.cancel()
            try:
                await self._resource_task
            except asyncio.CancelledError:
                pass

        # Scan /tmp BEFORE stopping server (this is the filesystem evidence)
        fs_entries = await self._scan_tmp()

        # Get process list
        processes = await self._get_processes()

        # Parse exfil sink logs (HOST-SIDE canary detection)
        exfil_captures = self._parse_sink_captures()

        # Stop server
        if self.server_process:
            try:
                self.server_process.terminate()
                await asyncio.wait_for(
                    self.server_process.wait(), timeout=5
                )
            except (asyncio.TimeoutError, ProcessLookupError):
                self.server_process.kill()

        # Stop Docker containers
        for container in [self.observer_container, self.sink_container]:
            if container:
                try:
                    container.stop(timeout=3)
                    container.remove(force=True)
                except Exception:
                    pass

        # The server container was --rm, so it auto-removes.
        # But force-remove if still hanging.
        try:
            c = self.docker_client.containers.get(self._server_container_name)
            c.remove(force=True)
        except docker.errors.NotFound:
            pass

        # Remove network (only if we created one)
        if self.network and not self._host_mode:
            try:
                self.network.remove()
            except Exception:
                pass

        return {
            "filesystem_entries": fs_entries,
            "exfil_captures": exfil_captures,
            "resource_snapshots": self.resource_snapshots,
            "processes": processes,
            "pcap_path": str(self.telemetry_dir / "capture.pcap"),
            "scan_errors": self._scan_errors,
        }

    async def _scan_tmp(self) -> list[FilesystemEntry]:
        """
        Scan /tmp inside the server container via docker exec.

        WHY NOT docker diff:
        - /tmp is a tmpfs mount, invisible to docker diff
        - docker diff has no permission/stat data
        - docker exec + find + stat gives us everything

        This is how MUST PASS #5 (filesystem write detection) works.

        Anti-flake: If docker exec fails, record the error visibly in
        self._scan_errors so it shows up in the report and tests can detect it.
        """
        entries: list[FilesystemEntry] = []
        try:
            # Use docker CLI since the container was launched via subprocess
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                self._server_container_name,
                "find",
                "/tmp",
                "-maxdepth",
                "3",
                "-type",
                "f",
                "-exec",
                "stat",
                "-c",
                "%n %s %a",
                "{}",
                ";",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=10
            )

            if proc.returncode != 0:
                error_msg = (
                    f"docker exec find/stat failed (exit {proc.returncode}): "
                    f"{stderr.decode(errors='replace').strip()}"
                )
                logger.error(error_msg)
                self._scan_errors.append(error_msg)

            for line in stdout.decode(errors="replace").splitlines():
                parts = line.strip().rsplit(maxsplit=2)
                if len(parts) != 3:
                    continue
                path, size_str, perm_str = parts
                try:
                    size = int(size_str)
                    perm_int = int(perm_str, 8)
                    is_exec = (perm_int & 0o111) != 0
                except ValueError:
                    continue

                # Get content hash
                hash_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    self._server_container_name,
                    "sha256sum",
                    path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                hash_out, _ = await asyncio.wait_for(
                    hash_proc.communicate(), timeout=5
                )
                content_hash = hash_out.decode().split()[0] if hash_out else ""

                # Get content preview (first 256 bytes)
                preview_proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "exec",
                    self._server_container_name,
                    "head",
                    "-c",
                    "256",
                    path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                preview_out, _ = await asyncio.wait_for(
                    preview_proc.communicate(), timeout=5
                )
                preview = (
                    preview_out.decode(errors="replace") if preview_out else ""
                )

                entries.append(
                    FilesystemEntry(
                        path=path,
                        size_bytes=size,
                        permissions=perm_str,
                        is_executable=is_exec,
                        content_hash=content_hash,
                        content_preview=preview[:256],
                    )
                )
        except Exception as e:
            error_msg = f"_scan_tmp failed: {type(e).__name__}: {e}"
            logger.error(error_msg)
            self._scan_errors.append(error_msg)

        return entries

    async def _get_processes(self) -> list[str]:
        """Get process list from the server container."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                self._server_container_name,
                "ps",
                "aux",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            return stdout.decode(errors="replace").splitlines()
        except Exception:
            return []

    def _parse_sink_captures(self) -> list[dict]:
        """
        Parse exfil sink container logs and do canary detection.
        Canary detection is HOST-SIDE (the sink is intentionally dumb).
        """
        if not self.sink_container:
            return []
        try:
            logs = self.sink_container.logs(stdout=True, stderr=False)
            return parse_sink_logs(logs, CANARY_ENV_VARS)
        except Exception:
            return []

    async def _monitor_resources(self):
        """Poll Docker stats for the server container."""
        try:
            while True:
                try:
                    container = self.docker_client.containers.get(
                        self._server_container_name
                    )
                    stats = container.stats(stream=False)
                    self.resource_snapshots.append(
                        ResourceSnapshot(
                            timestamp=datetime.now(timezone.utc),
                            cpu_percent=self._calc_cpu(stats),
                            memory_mb=stats.get("memory_stats", {}).get(
                                "usage", 0
                            )
                            / (1024 * 1024),
                            network_rx_bytes=self._net_stat(stats, "rx_bytes"),
                            network_tx_bytes=self._net_stat(stats, "tx_bytes"),
                            pids=stats.get("pids_stats", {}).get("current", 0),
                        )
                    )
                except docker.errors.NotFound:
                    break
                except Exception:
                    pass
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass

    def _get_container_ip(self, container) -> str:
        container.reload()
        for name, info in (
            container.attrs.get("NetworkSettings", {})
            .get("Networks", {})
            .items()
        ):
            if "sentinel_net" in name:
                return info.get("IPAddress", "127.0.0.1")
        return "127.0.0.1"

    @staticmethod
    def _calc_cpu(stats: dict) -> float:
        try:
            d = (
                stats["cpu_stats"]["cpu_usage"]["total_usage"]
                - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            )
            s = (
                stats["cpu_stats"]["system_cpu_usage"]
                - stats["precpu_stats"]["system_cpu_usage"]
            )
            return round((d / s) * 100, 2) if s > 0 else 0.0
        except (KeyError, ZeroDivisionError):
            return 0.0

    @staticmethod
    def _net_stat(stats: dict, key: str) -> int:
        return sum(
            iface.get(key, 0)
            for iface in stats.get("networks", {}).values()
        )
