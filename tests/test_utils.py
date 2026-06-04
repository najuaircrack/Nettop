from nettop.config import FilterConfig
from nettop.store import TrafficStore
from nettop.models import PacketEvent
from nettop.utils import parse_ports
from nettop.puregeo import PureGeoResolver


def test_parse_ports():
    assert parse_ports("80,443,8000-8002") == {80, 443, 8000, 8001, 8002}
    assert parse_ports("0") == set()


def test_filter_matches():
    fc = FilterConfig(dst="10.0.0.1", ports={443}, protocols={"TCP"})
    assert fc.matches("1.1.1.1", "10.0.0.1", "TCP", 443)
    assert not fc.matches("1.1.1.1", "10.0.0.2", "TCP", 443)


def test_store_snapshot():
    store = TrafficStore()
    store.record(PacketEvent(1_000_000_000, "1.1.1.1", "10.0.0.1", "TCP", 100, 1234, 443))
    snap = store.snapshot()
    assert snap["total_packets"] == 1
    assert snap["unique_ips"] == 1
    assert snap["ips"][0]["ip"] == "1.1.1.1"


def test_pure_geo_embedded():
    geo = PureGeoResolver().lookup("8.8.8.8")
    assert geo.country_code == "US"
    assert geo.source.startswith("location.csv:")
