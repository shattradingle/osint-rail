"""`python -m osint_rail` is the same entry point as the `osint-rail` script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
