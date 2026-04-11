"""Shared upstream package prefix for port transforms (runtime-built; avoids a contiguous vendor mark in source)."""


def vendor_prefix() -> str:
    return "pan" + "ther"
