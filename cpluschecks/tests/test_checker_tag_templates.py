from checkers.libpcap import Libpcap
from checkers.openssl import Openssl
from checkers.poco import Poco


def test_checker_tag_templates():
    assert Libpcap.TAG_TEMPLATE == "libpcap-{version}"
    assert Openssl.TAG_TEMPLATE == "openssl-{version}"
    assert Poco.TAG_TEMPLATE == "poco-{version}-release"
