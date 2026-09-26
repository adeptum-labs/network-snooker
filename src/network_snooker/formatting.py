UNITS = ("B", "KiB", "MiB", "GiB", "TiB")


def format_bytes(count: float) -> str:
    value = float(count)
    for unit in UNITS[:-1]:
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {UNITS[-1]}"


def format_rate(bytes_per_second: float) -> str:
    return f"{format_bytes(bytes_per_second)}/s"


def format_port(port: int | None) -> str:
    return "-" if port is None else str(port)
