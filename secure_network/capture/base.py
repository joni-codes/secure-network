"""Abstract base for all capture sources."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional


class CaptureSource(ABC):
    """Base class for any data source that feeds the detection engine."""

    def __init__(self, name: str):
        self.name = name
        self._running = False
        self._callbacks: List[Callable] = []

    @abstractmethod
    async def start(self) -> None:
        """Activate the capture source."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Deactivate the capture source and clean up."""
        ...

    @abstractmethod
    async def get_state(self) -> Dict[str, Any]:
        """Return the current state snapshot."""
        ...

    def on_data(self, callback: Callable) -> None:
        """Register a callback for incoming data packets."""
        self._callbacks.append(callback)

    def emit(self, data: Dict[str, Any]) -> None:
        """Push data to all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(data)
            except Exception:
                pass

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def capabilities_required(self) -> List[str]:
        """List of capability strings required for this capture source."""
        return []
