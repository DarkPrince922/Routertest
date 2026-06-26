"""Scan stages.

A stage is an ``async def stage(target: str) -> list[Finding]`` coroutine. Stages
are independent: if one raises, the runner records an ``info`` Finding and keeps
going (one failing tool must not abort the whole scan).
"""
from .nmap_stage import nmap_stage
from .nuclei_stage import nuclei_stage
from .routersploit_stage import routersploit_stage
from .snmp_stage import snmp_stage

__all__ = ["nmap_stage", "nuclei_stage", "routersploit_stage", "snmp_stage"]
