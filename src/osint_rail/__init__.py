"""osint-rail — evidence-first OSINT from one seed to a sourced dossier.

Every stored claim carries its source URL, fetch time and an excerpt. No source,
no claim. Entity merges are deterministic-key only; probabilistic links are
reported as scored candidates, never merged silently. A blocked source is
recorded as UNKNOWN, never as absence.
"""

__version__ = "2.0.0"

__all__ = ["__version__"]
