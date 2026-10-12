"""SSRF guard policy (ADR-0005): pure address policy plus resolution handling."""

from __future__ import annotations

import ipaddress

import pytest

from privacy_scanner.domain.evidence import BlockReason
from privacy_scanner.intake.ssrf_guard import NetworkPolicy, SsrfGuard, non_public_reason


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:169.254.169.254",  # IPv4-mapped
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
        "2002:a9fe:a9fe::",  # 6to4 of 169.254.169.254
        "198.18.0.1",  # benchmarking
    ],
)
def test_non_public_addresses_are_refused(address: str) -> None:
    assert non_public_reason(ipaddress.ip_address(address)) is not None


@pytest.mark.parametrize("address", ["93.184.215.14", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address: str) -> None:
    assert non_public_reason(ipaddress.ip_address(address)) is None


def test_allow_loopback_never_opens_metadata_or_private_ranges() -> None:
    def reason(a: str) -> str | None:
        return non_public_reason(ipaddress.ip_address(a), allow_loopback=True)

    assert reason("127.0.0.1") is None
    assert reason("::ffff:127.0.0.1") is None
    assert reason("169.254.169.254") is not None
    assert reason("10.0.0.1") is not None


def _guard(answers: dict[str, list[str]], **policy: object) -> SsrfGuard:
    async def resolver(host: str, port: int) -> list[str]:
        if host not in answers:
            raise OSError("NXDOMAIN")
        return answers[host]

    return SsrfGuard(policy=NetworkPolicy(**policy), resolver=resolver)  # type: ignore[arg-type]


async def test_public_host_is_allowed_with_its_addresses() -> None:
    decision = await _guard({"example.com": ["93.184.215.14"]}).check_url("https://example.com/")
    assert decision.allowed
    assert decision.addresses == ("93.184.215.14",)


async def test_mixed_public_and_private_answer_is_refused() -> None:
    guard = _guard({"rebind.example": ["93.184.215.14", "169.254.169.254"]})
    decision = await guard.check_url("https://rebind.example/")
    assert decision.reason is BlockReason.NON_PUBLIC_ADDRESS


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("ftp://example.com/", BlockReason.FORBIDDEN_SCHEME),
        ("https://example.com:22/", BlockReason.FORBIDDEN_PORT),
        ("http://localhost/", BlockReason.FORBIDDEN_HOST),
        ("http://metadata.google.internal/", BlockReason.FORBIDDEN_HOST),
        ("http://printer.local/", BlockReason.FORBIDDEN_HOST),
        ("http://intranet/", BlockReason.FORBIDDEN_HOST),
        ("http://0xa9fea9fe/", BlockReason.NON_PUBLIC_ADDRESS),
        ("http://[::ffff:a9fe:a9fe]/", BlockReason.NON_PUBLIC_ADDRESS),
        ("https://nxdomain.example/", BlockReason.DNS_FAILURE),
        ("wss://localhost/socket", BlockReason.FORBIDDEN_HOST),
    ],
)
async def test_forbidden_destinations_are_refused(url: str, reason: BlockReason) -> None:
    decision = await _guard({}).check_url(url)
    assert not decision.allowed
    assert decision.reason is reason


async def test_decisions_are_cached_per_host_and_port() -> None:
    calls: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append(host)
        return ["93.184.215.14"]

    guard = SsrfGuard(resolver=resolver)
    await guard.check_url("https://example.com/a")
    await guard.check_url("https://example.com/b")
    assert calls == ["example.com"]
