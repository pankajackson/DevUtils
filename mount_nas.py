#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import argparse
import configparser
import getpass
import tempfile
from dataclasses import dataclass
from pathlib import Path


# --------------------------
# Constants
# --------------------------
CONFIG_FILE = Path.home() / ".config/syno-cli/config.ini"
MOUNT_BASE = Path.home() / "NAS"


# --------------------------
# Data Models
# --------------------------
@dataclass
class Profile:
    name: str
    host: str
    user: str
    password: str | None
    domain: str
    shares: list[str]


@dataclass
class Session:
    password: str | None = None


# --------------------------
# Config Manager
# --------------------------
class ConfigManager:
    def __init__(self, path: Path):
        self.path = path
        self.config = configparser.ConfigParser()

    def load(self) -> None:
        self.config.read(self.path)

    def save(self) -> None:
        with open(self.path, "w") as f:
            self.config.write(f)
        os.chmod(self.path, 0o600)

    def list_profiles(self) -> list[str]:
        return self.config.sections()

    def get_profile(self, name: str) -> Profile | None:
        if name not in self.config:
            return None

        section = self.config[name]

        shares = [s.strip() for s in section.get("shares", "").split(",") if s.strip()]

        return Profile(
            name=name,
            host=section.get("host", ""),
            user=section.get("user", ""),
            password=section.get("pass", None),
            domain=section.get("domain", "WORKGROUP"),
            shares=shares,
        )

    def save_profile(self, profile: Profile) -> None:
        self.config[profile.name] = {
            "host": profile.host,
            "user": profile.user,
            "pass": profile.password or "",
            "domain": profile.domain,
            "shares": ",".join(profile.shares),
        }
        self.save()


# --------------------------
# Mount Manager
# --------------------------
class MountManager:
    def __init__(self, session: Session):
        self.session = session

    def is_mounted(self, path: Path) -> bool:
        result = subprocess.run(["mount"], capture_output=True, text=True)
        return f"on {path} " in result.stdout

    def resolve_password(
        self,
        cli_pass: str | None,
        profile_pass: str | None,
    ) -> str:
        # priority: CLI > session > config > prompt
        if cli_pass:
            return cli_pass

        if self.session.password:
            return self.session.password

        if profile_pass:
            return profile_pass

        self.session.password = getpass.getpass("Enter password: ")
        return self.session.password

    def mount(self, profile: Profile, share: str, args) -> None:
        mount_point = MOUNT_BASE / share
        mount_point.mkdir(parents=True, exist_ok=True)

        if self.is_mounted(mount_point):
            print(f"⚠️  {share} already mounted")
            return

        host = args.host or profile.host
        user = args.username or profile.user
        domain = args.domain or profile.domain

        password = self.resolve_password(
            args.password,
            profile.password,
        )

        if not host:
            host = input("Enter NAS host/IP: ").strip()

        if not user:
            user = input("Enter username: ").strip()

        if not host or not user:
            print("❌ Missing required details")
            return

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as cred:
            cred.write(f"username={user}\npassword={password}\ndomain={domain}\n")
            cred_path = cred.name

        os.chmod(cred_path, 0o600)

        try:
            subprocess.run(
                [
                    "sudo",
                    "mount",
                    "-t",
                    "cifs",
                    f"//{host}/{share}",
                    str(mount_point),
                    "-o",
                    f"credentials={cred_path},vers=3.0,sec=ntlmssp,uid={os.getuid()},gid={os.getgid()},iocharset=utf8,file_mode=0775,dir_mode=0775",
                ],
                check=True,
            )
            print(f"✅ Mounted {share} → {mount_point}")

        except subprocess.CalledProcessError:
            print(f"❌ Failed to mount //{host}/{share}")
            subprocess.run("dmesg | tail -n 20", shell=True)

        finally:
            os.remove(cred_path)

    def mount_all(self, profile: Profile, args) -> None:
        if not profile.shares:
            print("❌ No shares defined")
            return

        need_mount = any(not self.is_mounted(MOUNT_BASE / s) for s in profile.shares)

        if need_mount and not self.session.password:
            self.session.password = getpass.getpass("Enter password: ")

        for share in profile.shares:
            self.mount(profile, share, args)


# --------------------------
# CLI
# --------------------------
class CLI:
    def __init__(self):
        self.config = ConfigManager(CONFIG_FILE)
        self.session = Session()
        self.mounter = MountManager(self.session)

    def setup(self) -> None:
        MOUNT_BASE.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.touch(exist_ok=True)
        self.config.load()

    def run(self) -> None:
        parser = argparse.ArgumentParser(prog="syno")
        sub = parser.add_subparsers(dest="command")

        # mount
        mount_cmd = sub.add_parser("mount")
        mount_cmd.add_argument("share")

        # all
        all_cmd = sub.add_parser("all")

        # config
        sub.add_parser("config")

        # list
        sub.add_parser("list")

        # shared args
        for p in [mount_cmd, all_cmd]:
            p.add_argument("-p", "--profile", default="default")
            p.add_argument("-H", "--host")
            p.add_argument("-U", "--username")
            p.add_argument("-P", "--password")
            p.add_argument("-D", "--domain")

        args = parser.parse_args()

        if args.command == "config":
            self.handle_config()
            return

        if args.command == "list":
            self.handle_list()
            return

        profile = self.config.get_profile(args.profile)
        if not profile:
            print(f"❌ Profile '{args.profile}' not found")
            return

        if args.command == "mount":
            self.mounter.mount(profile, args.share, args)

        elif args.command == "all":
            self.mounter.mount_all(profile, args)

        else:
            parser.print_help()

    def handle_config(self) -> None:
        name = input("Profile name: ").strip()
        host = input("Host: ").strip()
        user = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        domain = input("Domain [WORKGROUP]: ").strip() or "WORKGROUP"
        shares = input("Shares (comma separated): ").strip()

        profile = Profile(
            name=name,
            host=host,
            user=user,
            password=password,
            domain=domain,
            shares=[s.strip() for s in shares.split(",") if s.strip()],
        )

        self.config.save_profile(profile)
        print("✅ Profile saved")

    def handle_list(self) -> None:
        for p in self.config.list_profiles():
            print(p)


# --------------------------
# Entry
# --------------------------
def main() -> None:
    cli = CLI()
    cli.setup()
    cli.run()


if __name__ == "__main__":
    main()
