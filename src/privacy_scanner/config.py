"""Runtime configuration (12-factor: environment variables, ``PRIVACY_SCANNER_`` prefix).

Defaults reproduce a first-time visitor from France on a desktop browser,
which is the vantage point the rule catalog is written for (design review
§2.4, risk R6). Changing any of them changes what sites show, so every value
that can influence behaviour is copied into the Evidence Bundle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from privacy_scanner.intake.ssrf_guard import NetworkPolicy


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PRIVACY_SCANNER_", frozen=True, extra="ignore")

    # Vantage point -------------------------------------------------------- #
    vantage_point: str = Field(
        default="local",
        description="Free-text label of where scans run, printed in every report "
        "(production: 'gcp:europe-west9 (Paris, FR)').",
    )
    locale: str = "fr-FR"
    timezone: str = "Europe/Paris"
    accept_language: str = "fr-FR,fr;q=0.9,en;q=0.8"
    viewport_width: int = Field(default=1366, gt=0)
    viewport_height: int = Field(default=768, gt=0)

    # Timing (seconds) ----------------------------------------------------- #
    navigation_timeout_s: float = Field(default=30.0, gt=0)
    network_idle_timeout_s: float = Field(default=10.0, ge=0)
    observation_window_s: float = Field(
        default=6.0,
        ge=0,
        description="Extra time the page is observed after load/network-idle, without "
        "interaction, to catch deferred tags (risk R2).",
    )
    cookie_poll_interval_s: float = Field(default=0.25, gt=0)

    # Limits --------------------------------------------------------------- #
    max_requests_per_session: int = Field(default=3000, gt=0)
    max_dom_bytes: int = Field(default=5_000_000, gt=0)
    max_frames: int = Field(default=50, gt=0)

    # Browser -------------------------------------------------------------- #
    headless: bool = True
    extra_chromium_args: Annotated[tuple[str, ...], NoDecode] = ()

    # Network guard -------------------------------------------------------- #
    allowed_ports: Annotated[frozenset[int] | None, NoDecode] = frozenset({80, 443})
    allow_loopback: bool = Field(
        default=False, description="Development/tests only. Never enable in production."
    )

    # Output --------------------------------------------------------------- #
    output_dir: Path = Path("scans")

    @field_validator("extra_chromium_args", mode="before")
    @classmethod
    def _split_args(cls, value: Any) -> Any:
        if isinstance(value, str):
            return tuple(arg for arg in value.split() if arg)
        return value

    @field_validator("allowed_ports", mode="before")
    @classmethod
    def _parse_ports(cls, value: Any) -> Any:
        """Accept ``"80,443"`` or ``"any"`` from the environment."""
        if isinstance(value, str):
            if value.strip().lower() == "any":
                return None
            return frozenset(int(port) for port in value.split(",") if port.strip())
        return value

    def network_policy(self) -> NetworkPolicy:
        return NetworkPolicy(allowed_ports=self.allowed_ports, allow_loopback=self.allow_loopback)
