#!/usr/bin/env python3
"""
Requirements:
- pam (sudo pacman -S python-pam)
- tar
"""
import os, subprocess
import pam
import getpass
from enum import Enum
from pathlib import Path
import logging
from dataclasses import dataclass
import argparse


DEFAULT_PASSWORD = "123"


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("locker" if __name__ == "__main__" else __name__)


class Action(Enum):
    lock = "lock"
    unlock = "unlock"


@dataclass
class AuthData:
    username: str
    password: str


class Locker:
    def __init__(self, path: Path, action: Action):
        self.path = path
        self.tar_path = self.path.with_suffix(".tar")
        self.encrypted_tar_path = self.tar_path.with_suffix(".enc")
        self.action = action

        if action == Action.lock:
            self.lock()
        elif action == Action.unlock:
            self.unlock()
        else:
            raise ValueError("Invalid action.")

    def _secure_auth_data_input(self):
        try:
            username = getpass.getuser()
            password = getpass.getpass(
                prompt=f"Enter your password for user {username}: ", stream=None
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
    ) -> AuthData | None:
        pam_authenticator = pam.pam()
        auth_data = self._secure_auth_data_input()
        if pam_authenticator.authenticate(auth_data.username, auth_data.password):
            return auth_data
        else:
            logger.error("Authentication failed.")
            exit(2)

    def tar(self):
        subprocess.run(
            [
                "tar",
                "-cf",
                self.tar_path,
                "-C",
                self.path.parent,
                self.path.name,
            ]
        )

    def untar(self):
        subprocess.run(
            [
                "tar",
                "-xf",
                self.tar_path,
                "-C",
                self.path.parent,
            ]
        )

    def encrypt(self, password):
        subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-256-cbc",
                "-salt",
                "-in",
                self.tar_path,
                "-out",
                self.encrypted_tar_path,
                "-k",
                password,
            ]
        )

    def decrypt(self, password):
        subprocess.run(
            [
                "openssl",
                "enc",
                "-d",
                "-aes-256-cbc",
                "-in",
                self.encrypted_tar_path,
                "-out",
                self.tar_path,
                "-k",
                password,
            ]
        )

    def lock(self):
        auth_data = self.authenticate()
        if auth_data:
            if not auth_data.password:
                auth_data.password = DEFAULT_PASSWORD
            self.tar()
            self.encrypt(auth_data.password)
            os.remove(self.tar_path)
            os.system(f"rm -rf {self.path}")
            logger.info("Folder locked and encrypted.")
        else:
            logger.error("Authentication failed.")

    def unlock(self):
        auth_data = self.authenticate()
        if auth_data:
            if not auth_data.password:
                auth_data.password = DEFAULT_PASSWORD
            self.decrypt(auth_data.password)
            self.untar()
            os.remove(self.tar_path)
            os.remove(self.encrypted_tar_path)
            logger.info("Folder unlocked.")
        else:
            logger.error("Authentication failed.")


loc_obj = Locker(path=Path("/tmp/locker_test/something/"), action=Action.lock)
