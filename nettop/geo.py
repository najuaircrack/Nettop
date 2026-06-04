from __future__ import annotations

from collections import OrderedDict
from threading import Lock

from .models import GeoResult
from .puregeo import PureGeoResolver


class OfflineGeoResolver:
    """Offline resolver backed only by Nettop's own CSV/range module."""

    def __init__(self, location_db: str | None = None, disabled: bool = False):
        self.disabled = disabled
        self._cache: OrderedDict[str, GeoResult] = OrderedDict()
        self._lock = Lock()
        self._max_cache = 100_000
        self._pure = None if disabled else PureGeoResolver(location_db)
        self.source = "disabled" if disabled else self._pure.source

    def lookup(self, ip: str) -> GeoResult:
        if self.disabled or self._pure is None:
            return GeoResult(source="disabled")

        with self._lock:
            cached = self._cache.get(ip)
            if cached:
                self._cache.move_to_end(ip)
                return cached

        result = self._pure.lookup(ip)
        with self._lock:
            self._cache[ip] = result
            if len(self._cache) > self._max_cache:
                self._cache.popitem(last=False)
        return result

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)


def geo_status(resolver: OfflineGeoResolver) -> str:
    if resolver.disabled:
        return "disabled"
    return resolver.source

