"""Custom exceptions for VulnHunter."""

class VulnHunterException(Exception):
    """Base exception for VulnHunter."""
    pass

class TargetResolutionError(VulnHunterException):
    """Raised when target domain or IP cannot be resolved."""
    pass

class AuthorizationRequiredError(VulnHunterException):
    """Raised when active probing is attempted without authorization."""
    pass

class IntelDatabaseError(VulnHunterException):
    """Raised when local CVE database fails to initialize or query."""
    pass

class ScannerExecutionError(VulnHunterException):
    """Raised when a scanner component encounters an unrecoverable failure."""
    pass
