from io import BytesIO


def compress(src):
    if not hasattr(src, "read"):
        src = BytesIO(src)

    dst = bytearray()

    val = 0
    shift = 0
    while True:
        _byte = src.read(1)
        if not len(_byte):
            break

        val |= (_byte[0] & 0x7F) << shift
        shift += 7

        if shift >= 8:
            dst.append(val & 0xFF)
            val >>= 8
            shift -= 8

    if val:
        dst.append(val & 0xFF)

    return bytes(dst)


def decompress(src, wide=False):
    if not hasattr(src, "read"):
        src = BytesIO(src)

    dst = bytearray()

    val = 0
    shift = 0
    while True:
        _byte = src.read(1)
        if not len(_byte):
            break

        val |= _byte[0] << shift
        dst.append(val & 0x7F)
        if wide:
            dst.append(0)

        val >>= 7
        shift += 1
        if shift == 7:
            dst.append(val & 0x7F)
            if wide:
                dst.append(0)
            val >>= 7
            shift = 0

    return bytes(dst)
