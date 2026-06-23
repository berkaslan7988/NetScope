"""The contract every scanner backend implements."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import AccessPoint


class ScannerError(RuntimeError):
    """Raised when a scan cannot be performed (no adapter, permission, etc.)."""


class Scanner(ABC):
    @abstractmethod
    def scan(self) -> list[AccessPoint]:
        """Return the access points currently visible. May raise ScannerError."""
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def is_real(self) -> bool:
        """False for the mock backend, True for backends reading real hardware."""
        return True
