from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class BackupServerConfig(BaseModel):
    user: str
    host: str
    port: int = 22
    borg_bin: str = "borg"


class RepositoryConfig(BaseModel):
    base_dir: str
    name: str


class BackupConfig(BaseModel):
    paths: list[str] = Field(default_factory=list)
    excludes: list[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    directory: str


class BorgConfig(BaseModel):
    compression: str = "zstd,6"
    exclude_caches: bool = True


class Config(BaseModel):
    backup_server: BackupServerConfig
    repository: RepositoryConfig
    backup: BackupConfig
    logging: LoggingConfig
    borg: BorgConfig


def load_config(source: str | Path | dict[str, Any]) -> Config:
    """
    Load configuration from:

    - YAML file
    - JSON file
    - Python dictionary

    Returns:
        Config: Validated Pydantic configuration object.
    """

    if isinstance(source, dict):
        return Config.model_validate(source)

    path = Path(source)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Configuration path is not a file: {path}")

    suffix = path.suffix.lower()

    with path.open("r", encoding="utf-8") as file:
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(file)

        elif suffix == ".json":
            data = json.load(file)

        else:
            raise ValueError(
                f"Unsupported configuration format: {suffix}. "
                "Expected .yaml, .yml, or .json."
            )

    if not isinstance(data, dict):
        raise ValueError("Configuration root must be an object/mapping.")

    return Config.model_validate(data)
