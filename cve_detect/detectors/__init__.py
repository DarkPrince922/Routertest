"""Detector instances, one per CVE/family. Imported into the registry."""
from __future__ import annotations

from .asus_wrthug import AsusWrtHug
from .dlink_dir620_backdoor import DlinkDir620Backdoor
from .dlink_dir823x_cve_2025_29635 import DlinkDir823x
from .gpon_cve_2018_10561 import GponAuthBypass
from .huawei_hg532_cve_2017_17215 import HuaweiHg532Tr064
from .tplink_archer_cve_2023_1389 import TplinkArcherAx21
from .tplink_wireguard_cve_2025_7850 import TplinkWireguard
from .xiongmai_tbk_dvr import XiongmaiTbkDvr

# Order is display order; the registry filters by applicability per host.
ALL_DETECTORS = [
    TplinkArcherAx21(),
    TplinkWireguard(),
    DlinkDir823x(),
    HuaweiHg532Tr064(),
    GponAuthBypass(),
    AsusWrtHug(),
    DlinkDir620Backdoor(),
    XiongmaiTbkDvr(),
]

__all__ = ["ALL_DETECTORS"]
