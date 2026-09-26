import pytest

from network_snooker.formatting import format_bytes, format_port, format_rate


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (3 * 1024**2, "3.0 MiB"),
        (1024**5, "1024.0 TiB"),
    ],
)
def test_format_bytes(count, expected):
    assert format_bytes(count) == expected


def test_format_rate():
    assert format_rate(2048) == "2.0 KiB/s"


def test_format_port():
    assert format_port(443) == "443"
    assert format_port(None) == "-"
