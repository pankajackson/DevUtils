from borg_manager.config import load_config



config = load_config("config/config.yaml")

print(config)
print()

print("Backup server:")
print(f"  Host:     {config.backup_server.host}")
print(f"  Port:     {config.backup_server.port}")
print(f"  User:     {config.backup_server.user}")
print(f"  Borg:     {config.backup_server.borg_bin}")

print()

print("Repository:")
print(f"  Base dir: {config.repository.base_dir}")
print(f"  Name:     {config.repository.name}")

print()

print("Backup:")
print(f"  Paths:    {config.backup.paths}")
print(f"  Excludes: {config.backup.excludes}")

print()

print("Borg:")
print(f"  Compression:     {config.borg.compression}")
print(f"  Exclude caches:  {config.borg.exclude_caches}")