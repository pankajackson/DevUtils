import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lxa-borg",
        description="Borg Backup Manager",
    )

    # Global arguments
    parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to configuration file",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
    )

    # init
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a Borg repository",
    )

    # create
    create_parser = subparsers.add_parser(
        "create",
        help="Create a new backup archive",
    )

    create_parser.add_argument(
        "--comment",
        help="Comment to attach to the archive",
    )

    # list
    list_parser = subparsers.add_parser(
        "list",
        help="List backup archives",
    )

    # info
    info_parser = subparsers.add_parser(
        "info",
        help="Show repository or archive information",
    )

    # check
    check_parser = subparsers.add_parser(
        "check",
        help="Check repository integrity",
    )

    # prune
    prune_parser = subparsers.add_parser(
        "prune",
        help="Prune old backup archives",
    )

    # delete
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete a backup archive",
    )

    delete_parser.add_argument(
        "archive",
        help="Archive to delete",
    )

    # status
    status_parser = subparsers.add_parser(
        "status",
        help="Show backup status",
    )

    # key-export
    key_parser = subparsers.add_parser(
        "key-export",
        help="Export the Borg repository key",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    print(args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
