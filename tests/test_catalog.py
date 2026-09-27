import pytest

from network_snooker.catalog import BUNDLED_SERVICES, CatalogError, load_catalog


def write_toml(path, text):
    path.write_text(text)
    return path


def test_bundled_catalog_loads_and_covers_expected_services():
    catalog = load_catalog(override=BUNDLED_SERVICES.parent / "does-not-exist.toml")
    assert catalog["minecraft"].name == "Minecraft"
    assert catalog["tiktok"].category == "social"
    keys = {service.key for service in catalog}
    assert {"minecraft", "roblox", "steam", "tiktok", "instagram", "facebook", "discord"} <= keys


def test_bundled_catalog_ports_parse_correctly():
    catalog = load_catalog(override=BUNDLED_SERVICES.parent / "does-not-exist.toml")
    ports = catalog["minecraft"].ports
    assert ("tcp", 25565, 25565) in [(p.protocol, p.start, p.end) for p in ports]
    assert ("udp", 19132, 19133) in [(p.protocol, p.start, p.end) for p in ports]


def test_missing_name_is_rejected(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[foo]\ncategory = "game"\n')
    with pytest.raises(CatalogError, match="missing 'name'"):
        load_catalog(bundled=bundled, override=tmp_path / "missing.toml")


def test_bad_category_is_rejected(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[foo]\nname = "Foo"\ncategory = "shopping"\n')
    with pytest.raises(CatalogError, match="bad category"):
        load_catalog(bundled=bundled, override=tmp_path / "missing.toml")


def test_bad_port_spec_is_rejected(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[foo]\nname = "Foo"\ncategory = "game"\nports = ["carrier-pigeon/1"]\n')
    with pytest.raises(CatalogError, match="bad protocol"):
        load_catalog(bundled=bundled, override=tmp_path / "missing.toml")


def test_reversed_port_range_is_rejected(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[foo]\nname = "Foo"\ncategory = "game"\nports = ["tcp/200-100"]\n')
    with pytest.raises(CatalogError, match="bad port range"):
        load_catalog(bundled=bundled, override=tmp_path / "missing.toml")


def test_bad_cidr_is_rejected(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[foo]\nname = "Foo"\ncategory = "social"\ncidrs = ["not-a-cidr"]\n')
    with pytest.raises(CatalogError, match="bad CIDR"):
        load_catalog(bundled=bundled, override=tmp_path / "missing.toml")


def test_invalid_toml_is_rejected(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", "this is not [ toml")
    with pytest.raises(CatalogError, match="invalid TOML"):
        load_catalog(bundled=bundled, override=tmp_path / "missing.toml")


def test_override_merges_by_key(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[minecraft]\nname = "Minecraft"\ncategory = "game"\n')
    override = write_toml(tmp_path / "override.toml", '[minecraft]\nname = "Minecraft"\ncategory = "game"\nports = ["tcp/25566"]\n\n[custom]\nname = "Custom"\ncategory = "social"\n')
    catalog = load_catalog(bundled=bundled, override=override)
    assert catalog["minecraft"].ports[0].start == 25566
    assert "custom" in catalog


def test_missing_override_is_ignored(tmp_path):
    bundled = write_toml(tmp_path / "services.toml", '[minecraft]\nname = "Minecraft"\ncategory = "game"\n')
    catalog = load_catalog(bundled=bundled, override=tmp_path / "does-not-exist.toml")
    assert catalog["minecraft"].ports == ()
