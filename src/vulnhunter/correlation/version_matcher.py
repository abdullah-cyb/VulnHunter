"""Semantic version matching and specification evaluation engine."""

from packaging.version import Version, parse as parse_version
from typing import Optional

def is_version_vulnerable(detected_ver: Optional[str], spec_str: str) -> bool:
    """
    Evaluates whether a detected version string satisfies a version specifier.
    e.g. spec_str = "==2.4.49" or ">=1.0.1,<=1.0.1f" or ">=0.6.18,<=1.20.0"
    """
    if not detected_ver or not spec_str or spec_str == "*":
        return True

    # Normalize version string (strip trailing 'p1' or '-beta' for packaging compatibility if needed)
    ver_clean = detected_ver.split("p")[0].split("-")[0]
    
    try:
        ver_obj = parse_version(ver_clean)
    except Exception:
        # Fallback exact string match
        return detected_ver == spec_str.replace("==", "")

    # Multi-condition specs split by comma
    conditions = spec_str.split(",")
    for cond in conditions:
        cond = cond.strip()
        if cond.startswith("=="):
            target = cond[2:]
            if ver_clean != target:
                return False
        elif cond.startswith("<="):
            target = cond[2:]
            try:
                if not (ver_obj <= parse_version(target)):
                    return False
            except Exception:
                pass
        elif cond.startswith("<"):
            target = cond[1:]
            try:
                if not (ver_obj < parse_version(target)):
                    return False
            except Exception:
                pass
        elif cond.startswith(">="):
            target = cond[2:]
            try:
                if not (ver_obj >= parse_version(target)):
                    return False
            except Exception:
                pass
        elif cond.startswith(">"):
            target = cond[1:]
            try:
                if not (ver_obj > parse_version(target)):
                    return False
            except Exception:
                pass

    return True
