import io
import struct
from typing import BinaryIO, Union


def read_sid(fh: Union[BinaryIO, bytes], endian: str = "<") -> str:
    """Read a Windows SID from bytes.

    Normally we'd do this with cstruct, but do it with just struct to keep dissect.util dependency-free.
    On the upside, this also improves performance!

    This is equivalent to the following structure::

        typedef struct _SID {
            BYTE        Revision;
            BYTE        SubAuthorityCount;
            CHAR        IdentifierAuthority[6];
            DWORD       SubAuthority[SubAuthorityCount];
        } SID;

    Args:
        fh: A file-like object or bytes object to read the SID from.
        endian: Optional endianness for reading the sub authorities.
    """
    if isinstance(fh, bytes):
        fh = io.BytesIO(fh)

    revision, sub_authority_count, authority = struct.unpack("BB6s", fh.read(8))

    sub_authorities = struct.unpack(f"{endian}{sub_authority_count}I", fh.read(sub_authority_count * 4))

    sid_elements = [
        "S",
        f"{revision}",
        f"{authority[-1]}",
    ]
    sid_elements.extend(map(str, sub_authorities))
    readable_sid = "-".join(sid_elements)

    return readable_sid
