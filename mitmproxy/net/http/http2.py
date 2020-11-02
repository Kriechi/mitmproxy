import codecs

from mitmproxy import exceptions


def read_raw_frame(rfile):
    """
    Reads a full HTTP/2 frame from a file-like object.

    Returns raw header bytes and raw body bytes
    """

    header = rfile.safe_read(9)
    length = int(codecs.encode(header[:3], 'hex_codec'), 16)

    if length == 4740180:
        raise exceptions.HttpException("Length field looks more like HTTP/1.1:\n{}".format(rfile.read(-1)))

    body = rfile.safe_read(length)
    return [header, body]
