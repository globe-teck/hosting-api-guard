"""hosting-api-guard: a safety wrapper for hosting control-panel APIs used by AI agents."""
from .guard import Guard, GuardConfig, GuardError, Blocked, RateLimited
from .redact import redact
__all__ = ["Guard", "GuardConfig", "GuardError", "Blocked", "RateLimited", "redact"]
__version__ = "0.1.0"
