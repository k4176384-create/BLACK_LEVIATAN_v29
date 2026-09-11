from core.validation import confidence_engine, validate_finding
from core.edge_detector import detect_edge

def test_confidence():
    c = confidence_engine("dns", 0.95, 2, 0)
    assert 0.5 < c <= 1.0

def test_validate_port_no_banner_high():
    v = validate_finding("open_port", "1.2.3.4:21", {"port":21, "has_banner":False})
    assert v["validation_state"]=="INFERRED"
    assert "anycast" in v["limitations"]

def test_edge_cloudflare():
    det = detect_edge({"cf-ray":"123"}, asn="AS13335 Cloudflare, Inc.", ip="104.20.23.1")
    assert det["is_edge"] and det["provider"]=="cloudflare"

def test_crtsh_validation():
    v = validate_finding("subdomain_ct", "bad@value", {})
    assert v["validation_state"]=="CONTRADICTED"
