import pytest
from analyzer.url_analyzer import analyze_url


def test_normal_url():
    result = analyze_url("https://example.com")
    assert result["hostname"] == "example.com"
    assert result["scheme"] == "https"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["indicators"] == []


def test_url_without_scheme():
    result = analyze_url("example.com")
    assert result["hostname"] == "example.com"
    assert result["scheme"] == "https"


def test_ip_address_url():
    result = analyze_url("http://192.0.2.10/login?next=%2Faccount")
    assert result["hostname"] == "192.0.2.10"
    assert 0 < result["risk_score"] <= 100
    assert result["risk_level"] in {
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    }
    names = [item["name"] for item in result["indicators"]]
    assert "IP address used as hostname" in names
    assert "Unencrypted HTTP" in names
    assert "Security-sensitive keywords" in names
    assert "Percent-encoded characters" in names


def test_empty_url_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_url("")


def test_unsupported_scheme_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_url("ftp://example.com")


def test_malformed_port_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_url("https://example.com:invalid")


def test_embedded_credentials_are_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_url("https://user:password@example.com")


def test_invalid_hostname_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        analyze_url("https://invalid_domain.com")


def test_long_url_adds_indicator():
    url = "https://example.com/" + ("a" * 110)
    result = analyze_url(url)

    names = [item["name"] for item in result["indicators"]]
    assert "Long URL" in names


def test_risk_score_is_bounded():
    result = analyze_url(
        "http://192.0.2.10/login/verify/account/password/"
        + ("a" * 250)
    )

    assert 0 <= result["risk_score"] <= 100
