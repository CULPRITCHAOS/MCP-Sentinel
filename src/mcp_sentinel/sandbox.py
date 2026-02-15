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
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import docker

from mcp_sentinel.exfil_sink import SINK_PORT, SINK_SERVER_CODE, parse_sink_logs
from mcp_sentinel.models import FilesystemEntry, ResourceSnapshot


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
        self.network = self.docker_client.networks.create(
            self._network_name,
            driver="bridge",
            internal=True,
        )

        # 2. Start exfil sink
        sink_name = f"sentinel_sink_{run_id}"
        self.sink_container = self.docker_client.containers.run(
            "python:3.11-slim",
            command=["python", "-u", "-c", SINK_SERVER_CODE],
            detach=True,
            network=self._network_name,
            name=sink_name,
            labels={"sentinel.role": "exfil-sink"},
        )

        # Wait for sink to be ready
        await asyncio.sleep(1)

        # Get sink IP
        self.sink_container.reload()
        sink_ip = self._get_container_ip(self.sink_container)

        # 3. Start observer sidecar (pcap -- Phase 2 parsing)
        observer_name = f"sentinel_observer_{run_id}"
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
                str(self.telemetry_dir): {"bind": "/telemetry", "mode": "rw"}
            },
            labels={"sentinel.role": "observer"},
        )

        # 4. Build extra_hosts mapping (trapped domains -> sink)
        extra_hosts = [f"{domain}:{sink_ip}" for domain in TRAPPED_DOMAINS]

        # 5. Launch MCP server via subprocess docker run -i
        docker_cmd = [
            "docker",
            "run",
            "-i",  # Interactive (stdin open)
            "--rm",  # Cleanup on exit
            f"--name={self._server_container_name}",
            f"--network={self._network_name}",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            "--pids-limit=100",
            "--read-only",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64M",
            "--security-opt=no-new-privileges:true",
            "--cap-drop=ALL",
        ]

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

    async def stop(self) -> dict:
        """
        Tear down sandbox and return all telemetry.

        Returns dict with:
        - filesystem_entries: list[FilesystemEntry]
        - exfil_captures: list[dict] (with canary analysis)
        - resource_snapshots: list[ResourceSnapshot]
        - processes: list[str]
        - pcap_path: str
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

        # Remove network
        if self.network:
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
        }

    async def _scan_tmp(self) -> list[FilesystemEntry]:
        """
        Scan /tmp inside the server container via docker exec.

        WHY NOT docker diff:
        - /tmp is a tmpfs mount, invisible to docker diff
        - docker diff has no permission/stat data
        - docker exec + find + stat gives us everything

        This is how MUST PASS #5 (filesystem write detection) works.
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

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
        except Exception:
            pass  # If exec fails, we get no FS data -- noted in report

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
