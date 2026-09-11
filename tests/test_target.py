from core.target import classify_target, TargetType
def test_domain():
    assert classify_target("example.com").type == TargetType.DOMAIN
def test_subdomain():
    assert classify_target("sub.example.com").type == TargetType.SUBDOMAIN
def test_ipv4():
    assert classify_target("8.8.8.8").type == TargetType.IPV4
def test_ipv6():
    assert classify_target("2001:db8::1").type == TargetType.IPV6
def test_email():
    assert classify_target("user@example.com").type == TargetType.EMAIL
def test_url():
    assert classify_target("https://example.com/path?q=1").type == TargetType.URL
def test_punycode():
    info = classify_target("xn--e1afmkfd.xn--80akhbyknj4f")
    assert info.is_punycode
def test_invisible():
    info = classify_target("example.com\u200b")
    assert info.normalized=="example.com"
    assert any("invisible" in w.lower() for w in info.warnings)
def test_unknown():
    assert classify_target("not a domain!!").type == TargetType.UNKNOWN
def test_port():
    info = classify_target("example.com:8080")
    assert info.has_port and info.port==8080
