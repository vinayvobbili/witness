"""witness - a DFIR agent that can only report what it can prove a tool said."""

# The one place the version is written. pyproject reads it from here rather
# than carrying its own copy, because two versions in two files is a fact
# maintained in two places, and this repository has opinions about those.
__version__ = "0.2.0"

from .store import Store
from .verify import Binding, Verdict, submit_finding, verify

__all__ = ["Store", "Binding", "Verdict", "submit_finding", "verify", "__version__"]
