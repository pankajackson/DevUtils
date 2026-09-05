from lxa_utils.borg_manager.borg import Borg, BorgResult


def prune(borg: Borg, repository: str, *args: str) -> BorgResult:
    return borg.run(
        "prune",
        repository,
        *args,
    )
