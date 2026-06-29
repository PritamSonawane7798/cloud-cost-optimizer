from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.rules.base import Finding


class DestructivenessLevel(str, Enum):
    REVERSIBLE  = "reversible"   # stop / deallocate — can be undone
    DESTRUCTIVE = "destructive"  # delete — permanent, no native undo


@dataclass
class CommandEntry:
    finding:         Finding
    command:         str
    destructiveness: DestructivenessLevel
    rollback_note:   str | None = None
    warning:         str | None = None
