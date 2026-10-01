"""Tests adversariales de target classification."""
from __future__ import annotations
import pytest
from core.target import classify_target, TargetType, sanitize_for_modules, phases_for_target


class TestTargetClassification:
    """Tests de clasificación de targets con inputs adversariales."""

    def test_basic_domain(self):
        info = classify_target("example.com")
        assert info.type == TargetType.DOMAIN
        assert info.confidence >= 0.9

    def test_subdomain(self):
        info = classify_target("sub.example.com")
        assert info.type == TargetType.SUBDOMAIN

    def test_deep_subdomain(self):
        info = classify_target("a.b.c.example.com")
        assert info.type == TargetType.SUBDOMAIN

    def test_ipv4(self):
        info = classify_target("192.168.1.1")
        assert info.type == TargetType.IPV4
        assert info.confidence >= 0.99

    def test_ipv6(self):
        info = classify_target("2001:db8::1")
        assert info.type == TargetType.IPV6

    def test_email(self):
        info = classify_target("user@example.com")
        assert info.type == TargetType.EMAIL
        assert info.confidence >= 0.95

    def test_url_with_path(self):
        info = classify_target("https://example.com/path?q=1#fragment")
        assert info.type == TargetType.URL
        assert info.path == "/path"
        assert info.query == "q=1"
        assert info.fragment == "fragment"

    def test_url_with_port(self):
        info = classify_target("https://example.com:8080/path")
        assert info.type == TargetType.URL
        assert info.port == 8080
        assert info.has_port is True

    def test_username_with_at(self):
        info = classify_target("@username")
        assert info.type == TargetType.USERNAME
        assert info.host == "username"

    def test_bare_username(self):
        info = classify_target("username123")
        assert info.type == TargetType.USERNAME
        assert info.confidence < 0.7  # Low confidence for bare username

    def test_phone(self):
        info = classify_target("+1234567890")
        assert info.type == TargetType.PHONE

    def test_wallet_eth(self):
        info = classify_target("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38")
        assert info.type == TargetType.WALLET

    def test_wallet_btc(self):
        info = classify_target("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert info.type == TargetType.WALLET

    def test_hash_sha256(self):
        info = classify_target("a" * 64)
        assert info.type == TargetType.HASH

    def test_hash_md5(self):
        info = classify_target("a" * 32)
        assert info.type == TargetType.HASH

    def test_asn(self):
        info = classify_target("AS13335")
        assert info.type == TargetType.ASN

    def test_invisible_characters(self):
        info = classify_target("example.com\u200b\u200c\u200d")
        assert info.normalized == "example.com"
        assert any("invisible" in w.lower() for w in info.warnings)

    def test_unicode_normalization(self):
        info = classify_target("exаmple.com")  # Cyrillic 'а'
        assert info.type == TargetType.UNKNOWN  # No dominio ASCII válido
        assert any("clasi" in w.lower() for w in info.warnings)

    def test_punycode(self):
        info = classify_target("xn--e1afmkfd.xn--80akhbyknj4f")
        assert info.is_punycode is True

    def test_empty_input(self):
        info = classify_target("")
        assert info.type == TargetType.UNKNOWN
        assert info.confidence == 1.0

    def test_whitespace_only(self):
        info = classify_target("   ")
        assert info.type == TargetType.UNKNOWN

    def test_giant_url(self):
        giant_path = "a" * 10000
        info = classify_target(f"https://example.com/{giant_path}")
        assert info.type == TargetType.URL

    def test_special_characters(self):
        info = classify_target("example.com/path?q=hello world&lang=es")
        assert info.type == TargetType.URL

    def test_trailing_slash(self):
        info = classify_target("example.com/")
        assert info.type == TargetType.DOMAIN

    def test_www_prefix(self):
        info = classify_target("www.example.com")
        assert info.type == TargetType.SUBDOMAIN
        assert info.bare_domain == "example.com"

    def test_unknown_high_confidence(self):
        info = classify_target("not a domain!!")
        assert info.type == TargetType.UNKNOWN
        assert info.confidence >= 0.8

    def test_sanitize_domain(self):
        from core.target import TargetInfo, TargetType
        info = TargetInfo(
            raw="example.com",
            normalized="example.com",
            type=TargetType.DOMAIN,
            confidence=0.95,
            host="example.com",
        )
        assert sanitize_for_modules(info) == "example.com"

    def test_sanitize_email(self):
        from core.target import TargetInfo, TargetType
        info = TargetInfo(
            raw="user@example.com",
            normalized="user@example.com",
            type=TargetType.EMAIL,
            confidence=0.98,
            host="example.com",
        )
        assert sanitize_for_modules(info) == "example.com"

    def test_sanitize_url(self):
        from core.target import TargetInfo, TargetType
        info = TargetInfo(
            raw="https://example.com/path",
            normalized="https://example.com/path",
            type=TargetType.URL,
            confidence=0.97,
            host="example.com",
        )
        assert sanitize_for_modules(info) == "example.com"

    def test_phases_for_domain(self):
        phases = phases_for_target(TargetType.DOMAIN)
        assert phases == set(range(1, 11))

    def test_phases_for_email(self):
        phases = phases_for_target(TargetType.EMAIL)
        assert phases == {4, 5, 6}

    def test_phases_for_unknown(self):
        phases = phases_for_target(TargetType.UNKNOWN)
        assert phases == {1}
