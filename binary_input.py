"""Bounded read-only input ownership for offline evidence collectors."""
from contextlib import contextmanager
import os
import stat


class EvidenceError(ValueError):
    pass


@contextmanager
def open_binary_input(path, minimum, maximum):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not minimum <= info.st_size <= maximum:
            raise EvidenceError('Evidence collection requires a bounded regular input file')
        stream = os.fdopen(descriptor, 'rb')
        descriptor = None
        with stream:
            yield stream, info.st_size
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise EvidenceError('Truncated binary input')
    return data
