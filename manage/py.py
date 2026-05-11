"""Allow ``python -m manage.py <command>`` to work as a forgiving wrapper."""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import execute_from_command_line

    # ``python -m manage.py migrate`` sets argv[0] to this wrapper module. Django
    # only needs the remaining command arguments, so a manage.py-like argv keeps
    # help text and errors familiar.
    sys.argv[0] = "manage.py"
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
