#!/usr/bin/env python3
"""
Requirements:
- pam (sudo pacman -S python-pam)
- tar
"""
import os, subprocess, stat
import pam
import getpass
from enum import Enum
from pathlib import Path
import logging
from dataclasses import dataclass
import argparse
import hashlib
import fcntl


DEFAULT_PASSWORD = "123"
APP_DIR = Path.home() / ".config/lxa_locker"


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("locker" if __name__ == "__main__" else __name__)


class Action(Enum):
    lock = "lock"
    unlock = "unlock"
    status = "status"


class Status(Enum):
    e_locked = "e_locked"
    ne_locked = "ne_locked"
    unlocked = "unlocked"
    inprogress = "inprogress"
    notfound = "notfound"
    conflict = "conflict"
    unknown = "unknown"
    error = "error"


@dataclass
class AuthData:
    username: str
    password: str


class Locker:
    def __init__(
        self,
        path: Path,
        skip_auth: bool = False,
        skip_enc: bool = False,
        password: str | None = None,
    ) -> None:
        self.skip_auth = skip_auth
        self.skip_enc = skip_enc
        self.path = path.absolute()
        self.tar_path = self.path.parent / f".{self.path.name}.tar"
        self.encrypted_tar_path = self.tar_path.with_suffix(".enc")
        self.password = password

    def _secure_auth_data_input(self) -> AuthData:
        try:
            username = getpass.getuser()
            password = getpass.getpass(
                prompt=f"Enter password for user {username}: ", stream=None
            )
            return AuthData(username, password)
        except KeyboardInterrupt:
            logger.warning("\nOperation cancelled by user.")
            exit(2)
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            exit(1)

    def authenticate(
        self,
    ) -> AuthData:
        pam_authenticator = pam.pam()
        auth_data = self._secure_auth_data_input()
        if pam_authenticator.authenticate(auth_data.username, auth_data.password):
            return auth_data
        else:
            logger.error("Authentication failed.")
            exit(2)

    def tar(self) -> None:
        tar_process = subprocess.run(
            [
                "tar",
                "-cf",
                self.tar_path,
                "-C",
                self.path.parent,
                self.path.name,
            ],
            check=True,
        )
        if tar_process.returncode != 0:
            logger.error(
                f"Failed to untar {self.path.name}.\n" f"Error: {tar_process.stderr}"
            )
            exit(1)

    def untar(self) -> None:
        untar_process = subprocess.run(
            [
                "tar",
                "-xf",
                self.tar_path,
                "-C",
                self.path.parent,
            ],
            check=True,
        )
        if untar_process.returncode != 0:
            logger.error(
                f"Failed to untar {self.tar_path}.\n" f"Error: {untar_process.stderr}"
            )
            exit(1)

    def encrypt(self, password: str) -> None:
        self.tar()
        enc_process = subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-256-cbc",
                "-pbkdf2",
                "-iter",
                "100000",
                "-salt",
                "-in",
                self.tar_path,
                "-out",
                self.encrypted_tar_path,
                "-k",
                password,
            ],
            check=True,
        )
        if enc_process.returncode != 0:
            logger.error(
                f"Failed to encrypt {self.tar_path}.\n" f"Error: {enc_process.stderr}"
            )
            exit(1)

    def decrypt(self, password: str) -> None:
        desc_process = subprocess.run(
            [
                "openssl",
                "enc",
                "-d",
                "-aes-256-cbc",
                "-pbkdf2",
                "-iter",
                "100000",
                "-in",
                self.encrypted_tar_path,
                "-out",
                self.tar_path,
                "-k",
                password,
            ],
            check=True,
        )
        if desc_process.returncode != 0:
            logger.error("Failed to decrypt file.\n" f"Error: {desc_process.stderr}")
            exit(1)
        self.untar()

    def setup_permission(self, action: Action, enc: bool) -> None:
        target = self.encrypted_tar_path if enc else self.path
        perm = 0o000
        if action == Action.unlock:
            if self.path.is_file():
                perm = 0o600
            else:
                perm = 0o700
        os.chmod(target, perm)

    def cleanup(self, action: Action, enc: bool) -> None:
        if enc:
            if action == Action.lock:
                os.remove(self.tar_path)
                os.system(f"rm -rf {self.path}")
            elif action == Action.unlock:
                os.remove(self.tar_path)
                os.remove(self.encrypted_tar_path)

    def compute_md5_hexdigest(self, input_data: str | bytes) -> str:
        """Compute MD5 hash of input and return hexadecimal digest."""
        # Ensure input is in bytes
        if isinstance(input_data, str):
            byte_input = input_data.encode("utf-8")
        elif isinstance(input_data, bytes):
            byte_input = input_data
        else:
            raise TypeError("Input must be string or bytes")

        # Create MD5 hash and return hex digest
        md5_hash = hashlib.md5(byte_input)
        return md5_hash.hexdigest()

    def setup_password(self) -> str:
        if not self.skip_auth:
            auth_data = self.authenticate()
            self.password = auth_data.username if not self.password else self.password
        self.password = DEFAULT_PASSWORD if not self.password else self.password
        return self.password

    def acquire_process_lock(self):
        lock_file_name = f"{self.compute_md5_hexdigest(str(self.path))}.lock"
        lock_file = APP_DIR / lock_file_name
        if not os.path.exists(lock_file):
            open(lock_file, "a").close()

        lock_fd = open(lock_file, "r+")
        try:
            # Acquire an exclusive lock
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_fd
        except BlockingIOError:
            # Lock already acquired
            return None

    def release_process_lock(self, lock_fd) -> None:
        if lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()

    def status(self) -> Status:
        lock_fd = self.acquire_process_lock()
        if not lock_fd:
            return Status.inprogress
        try:
            if self.encrypted_tar_path.exists():
                if self.path.exists():
                    return Status.conflict
                else:
                    return Status.e_locked
            else:
                if not self.path.exists():
                    return Status.notfound
                else:
                    file_stat = os.stat(self.path)
                    permission_string = stat.filemode(file_stat.st_mode)
                    if permission_string[1:10] == "-" * 9:
                        return Status.ne_locked
                    else:
                        return Status.unlocked
        finally:
            self.release_process_lock(lock_fd)

    def lock(self) -> Status:
        status = self.status()
        if status != Status.unlocked:
            return status
        lock_fd = self.acquire_process_lock()
        if not lock_fd:
            return Status.inprogress
        try:
            if not self.skip_enc:
                self.encrypt(self.setup_password())
            elif not self.skip_auth:
                self.authenticate()
            self.setup_permission(action=Action.lock, enc=not self.skip_enc)
            self.cleanup(action=Action.lock, enc=not self.skip_enc)
            return Status.e_locked if not self.skip_enc else Status.ne_locked
        finally:
            self.release_process_lock(lock_fd)

    def unlock(self) -> Status:
        status = self.status()
        if status not in (Status.e_locked, Status.ne_locked):
            return status
        lock_fd = self.acquire_process_lock()
        if not lock_fd:
            return Status.inprogress
        try:
            self.setup_permission(action=Action.unlock, enc=Status.e_locked == status)
            if Status.e_locked == status:
                self.decrypt(self.setup_password())
            self.cleanup(action=Action.unlock, enc=Status.e_locked == status)
            return Status.unlocked
        finally:
            self.release_process_lock(lock_fd)


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LXA Super Secure Folder Locker",
    )
    parser.add_argument(
        "action",
        choices=["lock", "unlock", "status"],
        help="action to be performed.",
    )
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        help="path to lock or unlock.",
    )
    parser.add_argument(
        "-i",
        "--index",
        type=str,
        default=APP_DIR / "index.locker",
        help="path to Index file containing the list of files and folders to be locked or unlocked.",
    )
    parser.add_argument(
        "--skip-auth",
        action="store_true",
        help="skip user authentication.",
    )
    parser.add_argument(
        "--skip-enc",
        action="store_true",
        help="skip encryption.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="password to use for encryption.",
    )
    return parser.parse_args()


def main() -> None:
    args = get_args()
    action = Action(args.action)
    path_list: list[Path] = []
    if args.path:
        path_list.append(Path(args.path))
    else:
        path_index = Path(args.index)
        if not path_index.exists():
            logger.error(f"Index file {path_index} does not exist.")
            exit(1)
        elif not path_index.is_file():
            logger.error(f"Index file {path_index} is not a file.")
            exit(1)
        else:
            with open(path_index, "r") as f:
                path_list = [Path(line.strip()) for line in f.readlines()]

    for path in path_list:
        locker_obj_parameters = {
            "path": path,
            "skip_auth": args.skip_auth,
            "skip_enc": args.skip_enc,
        }
        if args.password:
            locker_obj_parameters["password"] = args.password
        locker_obj = Locker(**locker_obj_parameters)
        action_methods = {
            Action.lock: locker_obj.lock,
            Action.unlock: locker_obj.unlock,
            Action.status: locker_obj.status,
        }

        if action not in action_methods:
            raise ValueError("Invalid action.")

        result = action_methods[action]()
        print(f"{path} {result.value}")


if __name__ == "__main__":
    main()
