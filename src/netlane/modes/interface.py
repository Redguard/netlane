from pathlib import Path
from typing import Any, Optional, Protocol, Tuple

from netlane.config import Profile


class StepError(Exception):
    """A step cannot run in the current state. The message tells the user what to do."""


class Mode(Protocol):
    """A mode module. Only the steps listed in STEPS are implemented."""

    @property
    def SUMMARY(self) -> str: ...

    @property
    def STEPS(self) -> Tuple[str, ...]: ...

    def setup(self, name: str, profile: Profile[Any], distro: str) -> None: ...

    def pair(
        self,
        name: str,
        profile: Profile[Any],
        save_path: Optional[Path],
        force: bool,
    ) -> None: ...

    def up(self, name: str, profile: Profile[Any]) -> None:
        """Applies the profile and blocks until interrupted."""
        ...

    def down(self, name: str, profile: Profile[Any]) -> None: ...
