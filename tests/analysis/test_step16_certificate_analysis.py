from analysis.step16_certificate_analysis import (
    analyze_certificate,
    parse_certificate_from_apk,
    check_known_bad_certificate,
)

def test_analyze_certificate_no_apk():
    result = analyze_certificate("")
    assert result["certificate_found"] is False


def test_check_known_bad_certificate():
    result = check_known_bad_certificate("00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33")
    assert isinstance(result, dict)
    assert "known_bad" in result


def test_check_known_bad_certificate_empty():
    result = check_known_bad_certificate("")
    assert result["known_bad"] is False
