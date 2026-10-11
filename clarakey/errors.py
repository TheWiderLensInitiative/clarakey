class ClaraKeyError(Exception):
    """Messages must be safe to show: never include secret input."""


class InvalidVault(ClaraKeyError):
    pass


class AuthenticationError(ClaraKeyError):
    pass


class StorageError(ClaraKeyError):
    pass


class ValidationError(ClaraKeyError):
    pass
