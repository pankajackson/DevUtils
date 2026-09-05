from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass
class BorgResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.returncode == 0


class Borg:
    def __init__(self, binary: str = "borg"):
        self.binary = binary

    def run(
        self,
        *args: str,
        env: dict[str, str] | None = None,
    ) -> BorgResult:
        command = [self.binary, *args]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
        )

        return BorgResult(
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
        )