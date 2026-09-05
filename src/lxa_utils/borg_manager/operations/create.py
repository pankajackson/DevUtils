from lxa_utils.borg_manager.borg import Borg, BorgResult


def create(borg: Borg, repository: str, paths: list[str]) -> BorgResult:
    return borg.run(
        "create",
        repository,
        *paths,
    )
