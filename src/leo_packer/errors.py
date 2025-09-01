class LeoPackError(Exception):
    """Base class for Leo Pack errors."""


class ArgumentError(LeoPackError):
    pass


class CompressionError(LeoPackError):
    pass


class DecompressionError(LeoPackError):
    pass


class FormatError(LeoPackError):
    pass

