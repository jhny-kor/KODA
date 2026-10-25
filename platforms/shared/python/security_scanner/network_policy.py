"""Runtime gates for the Linux closed-network distribution.

Build-time download tools are intentionally outside this policy. Internal
GitLab, LDAP and Tracker transports have their own authenticated configuration.
"""
from __future__ import annotations

import os


class OfflineNetworkError(OSError):
    pass


def offline_mode() -> bool:
    from .data_release import managed_data_required
    if managed_data_required():
        return True
    return os.environ.get("KODA_OFFLINE_MODE", "0").strip().lower() not in {"0", "false", "no", "off"}


def require_online(feature: str) -> None:
    if offline_mode():
        raise OfflineNetworkError(f"{feature}: 폐쇄망 모드에서는 외부 조회가 차단됩니다. 반입한 로컬 자료를 사용하세요.")


def osv_disabled() -> bool:
    return offline_mode() or os.environ.get("KODA_EXCLUDE_OSV", "0").strip().lower() in {"1", "true", "yes", "on"}
