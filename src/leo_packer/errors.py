class PackError(Exception):
    """Base class for Leo Pack errors."""

LeoPackError = PackError

class ArgumentError(LeoPackError):
    pass


class CompressionError(LeoPackError):
    pass


class DecompressionError(LeoPackError):
    pass


class FormatError(LeoPackError):
    pass

