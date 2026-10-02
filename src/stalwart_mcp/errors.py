"""Error types. Every error a tool can return carries a stable `code` and a hint."""

from __future__ import annotations


class StalwartError(Exception):
    code = "STALWART_ERROR"

    def __init__(self, message: str, *, hint: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.details = details or {}

    def as_dict(self) -> dict:
        out: dict = {"error": self.code, "message": self.message}
        if self.hint:
            out["hint"] = self.hint
        if self.details:
            out["details"] = self.details
        return out


class CredentialMissing(StalwartError):
    code = "CREDENTIAL_MISSING"


class AuthRejected(StalwartError):
    """Stalwart answered 401/403.

    @warn Never retry. Stalwart bans the source IP after failed logins (on some
          installations after a single one), for every account behind that IP.
          A rejected credential is a state that needs a human, not a transient error.
    """

    code = "AUTH_REJECTED"


class IpBlocked(StalwartError):
    code = "IP_BLOCKED"


class RateLimited(StalwartError):
    code = "RATE_LIMITED"


class Unreachable(StalwartError):
    code = "UNREACHABLE"


class ResyncRequired(StalwartError):
    code = "RESYNC_REQUIRED"


class MethodError(StalwartError):
    """A JMAP method-level error (["error", {...}, callId])."""

    code = "JMAP_METHOD_ERROR"

    def __init__(self, method: str, type_: str, description: str | None = None, **kw):
        super().__init__(f"{method} failed: {type_}" + (f" ({description})" if description else ""), **kw)
        self.method = method
        self.type = type_
        self.description = description
        self.details = {"method": method, "type": type_, **self.details}


class SetError(StalwartError):
    """An object in a /set call was not created, updated or destroyed."""

    code = "JMAP_SET_ERROR"


class NotFound(StalwartError):
    code = "NOT_FOUND"


class InvalidInput(StalwartError):
    code = "INVALID_INPUT"


class Refused(StalwartError):
    """A safety rule of this server refused the action."""

    code = "REFUSED"


class Unsupported(StalwartError):
    code = "UNSUPPORTED"
