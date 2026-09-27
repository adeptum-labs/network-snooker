from network_snooker.host_pane import Peer, format_peer, protocol_mix, rate_series, top_peers
from network_snooker.tracker import HISTORY_SAMPLES, FlowView


def view(remote_ip="93.184.216.34", protocol="tcp", remote_port=443, rx_rate=0.0, tx_rate=0.0, rx_bytes=0, tx_bytes=0):
    return FlowView(protocol, "192.168.1.10", 51234, remote_ip, remote_port, rx_bytes, tx_bytes, rx_rate, tx_rate)


def test_protocol_mix_lists_most_common_first():
    flows = [view(protocol="udp"), view(), view(protocol="icmp", remote_port=None), view(), view(protocol="udp"), view()]
    assert protocol_mix(flows) == "tcp 3 · udp 2 · icmp 1"


def test_protocol_mix_without_flows():
    assert protocol_mix([]) == "none"


def test_top_peers_merges_flows_to_same_service():
    flows = [view(rx_rate=100.0, tx_rate=10.0, rx_bytes=1000, tx_bytes=100), view(rx_rate=50.0, tx_rate=5.0, rx_bytes=500)]
    assert top_peers(flows) == [Peer("93.184.216.34", "tcp", 443, 150.0, 15.0, 1600)]


def test_top_peers_orders_by_rate_then_bytes():
    flows = [view(remote_ip="8.8.8.8", rx_bytes=10), view(remote_ip="9.9.9.9", rx_rate=5.0), view(remote_ip="1.1.1.1", rx_bytes=9000)]
    assert [peer.remote_ip for peer in top_peers(flows)] == ["9.9.9.9", "1.1.1.1", "8.8.8.8"]


def test_top_peers_keeps_only_count():
    flows = [view(remote_ip=f"198.51.100.{index}", rx_rate=float(index)) for index in range(1, 8)]
    assert [peer.remote_ip for peer in top_peers(flows, count=2)] == ["198.51.100.7", "198.51.100.6"]


def test_format_peer_line():
    peer = Peer("93.184.216.34", "tcp", 443, 1153433.6, 40960.0, 0)
    assert format_peer(peer, "cdn.example.net") == "cdn.example.net   tcp/443    1.1 MiB/s ↓  40.0 KiB/s ↑"


def test_format_peer_cuts_long_names():
    peer = Peer("93.184.216.34", "tcp", 993, 0.0, 0.0, 0)
    assert format_peer(peer, "imap.example.com.example").startswith("imap.example.co…  tcp/993")


def test_format_peer_shows_protocol_without_port():
    peer = Peer("8.8.8.8", "icmp", None, 84.0, 84.0, 0)
    assert format_peer(peer, "dns.google") == "dns.google        icmp          84 B/s ↓      84 B/s ↑"


def test_rate_series_has_same_length_for_any_history():
    assert len(rate_series([5.0])) == len(rate_series([5.0] * HISTORY_SAMPLES))


def test_rate_series_puts_latest_sample_last():
    assert rate_series([5.0, 7.0])[-2:] == [5.0, 7.0]


def test_rate_series_anchors_steady_rate_at_zero():
    series = rate_series([1000.0] * HISTORY_SAMPLES)
    assert min(series) == 0.0
    assert series[-HISTORY_SAMPLES:] == [1000.0] * HISTORY_SAMPLES
