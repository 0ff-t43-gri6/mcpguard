"""Run a tool server inside a container instead of directly on the machine.

    [servers.files.sandbox]
    image = "node:22-slim"            # must contain the server's runtime
    network = false                    # default: no network at all
    mounts = [{ host = "C:/Users/me/Documents", container = "/data", write = false }]
    memory = "512m"
    runtime = "docker"                 # or "podman"

The server's ``command`` and ``args`` run inside the image. The container gets no network
unless asked, a read-only root filesystem, no Linux capabilities, a process limit, and sees
only the folders listed in ``mounts`` (read-only unless ``write = true``). The server's own
``env`` is passed by name, so values never appear in the process list.

This is the operating-system counterpart of ``allowed_paths``: that setting refuses calls
whose arguments point elsewhere; the sandbox means the server could not read elsewhere anyway.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Mount:
    host: str
    container: str
    write: bool = False


@dataclass(frozen=True)
class Sandbox:
    image: str
    network: bool = False
    mounts: tuple[Mount, ...] = field(default_factory=tuple)
    memory: str = "1g"
    runtime: str = "docker"

    def key(self) -> tuple:
        return (self.image, self.network, self.mounts, self.memory, self.runtime)

    def wrap(self, command: str, args: list[str], env_names: list[str]) -> tuple[str, list[str]]:
        """The runtime command line that runs ``command args`` inside the container."""
        run = ["run", "--rm", "-i", "--init", "--read-only", "--tmpfs", "/tmp",  # noqa: S108  # nosec B108
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
               "--memory", self.memory]
        if not self.network:
            run += ["--network", "none"]
        for m in self.mounts:
            run += ["--mount", f"type=bind,source={m.host},target={m.container}" + ("" if m.write else ",readonly")]
        for name in sorted(env_names):
            run += ["-e", name]  # by name: the value comes from the environment, not the command line
        return self.runtime, [*run, self.image, command, *args]


def parse(table: object, where: str) -> Sandbox:
    """Validate a ``[servers.<name>.sandbox]`` table. Raises ValueError naming the key."""
    if not isinstance(table, dict):
        raise ValueError(f"{where} must be a table")
    unknown = set(table) - {"image", "network", "mounts", "memory", "runtime"}
    if unknown:
        raise ValueError(f"{where}: unknown key '{sorted(unknown)[0]}'")
    image = table.get("image")
    if not isinstance(image, str) or not image or image.startswith("-") or any(c.isspace() for c in image):
        raise ValueError(f"{where}.image must name a container image")
    runtime = table.get("runtime", "docker")
    if runtime not in ("docker", "podman"):
        raise ValueError(f"{where}.runtime must be docker or podman")
    network = table.get("network", False)
    if not isinstance(network, bool):
        raise ValueError(f"{where}.network must be true or false")
    memory = table.get("memory", "1g")
    if not isinstance(memory, str) or not memory[:1].isdigit() or not memory.isalnum():
        raise ValueError(f"{where}.memory must look like 512m or 2g")
    mounts = []
    raw = table.get("mounts", [])
    if not isinstance(raw, list):
        raise ValueError(f"{where}.mounts must be a list")
    for i, m in enumerate(raw):
        at = f"{where}.mounts[{i}]"
        if not isinstance(m, dict) or not isinstance(m.get("host"), str) or not isinstance(m.get("container"), str):
            raise ValueError(f"{at} needs host and container paths")
        if set(m) - {"host", "container", "write"} or not isinstance(m.get("write", False), bool):
            raise ValueError(f"{at}: allowed keys are host, container and write (true or false)")
        if not (m["host"] + m["container"]).isprintable():
            raise ValueError(f"{at}: paths cannot contain control characters")
        if "," in m["host"] or "," in m["container"] or not m["host"] or not m["container"].startswith("/"):
            raise ValueError(f"{at}: paths cannot contain commas, and the container path must start with /")
        mounts.append(Mount(m["host"], m["container"], m.get("write", False)))
    return Sandbox(image, network, tuple(mounts), memory, runtime)
