"""`python -m deadweight` runs the same entry point as the `deadweight` command."""
import sys

from .cli import main

sys.exit(main())
