"""Minimal PEF container reader (big-endian, PowerPC CFM)."""
import struct, datetime

KINDS = {0: "code", 1: "unpackedData", 2: "patternData", 3: "constant", 4: "loader",
         5: "debug", 6: "executableData", 7: "exception", 8: "traceback"}

class Section:
    def __init__(self, idx, raw, blob):
        (self.name_off, self.default_addr, self.total_size, self.unpacked_size,
         self.packed_size, self.container_off, self.kind, self.share, self.align,
         _) = struct.unpack(">iIIIIIBBBB", raw)
        self.idx = idx
        self.raw = blob[self.container_off:self.container_off + self.packed_size]

    @property
    def kind_name(self):
        return KINDS.get(self.kind, str(self.kind))

    def data(self):
        if self.kind == 2:
            return unpack_pattern(self.raw, self.unpacked_size, self.total_size)
        return self.raw

def _arg(buf, pos):
    v = 0
    while True:
        b = buf[pos]; pos += 1
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, pos

def unpack_pattern(buf, unpacked, total):
    out = bytearray(); pos = 0
    while pos < len(buf):
        op = buf[pos] >> 5; cnt = buf[pos] & 0x1F; pos += 1
        if cnt == 0:
            cnt, pos = _arg(buf, pos)
        if op == 0:
            out += bytes(cnt)
        elif op == 1:
            out += buf[pos:pos + cnt]; pos += cnt
        elif op == 2:
            rep, pos = _arg(buf, pos)
            blk = buf[pos:pos + cnt]; pos += cnt
            out += blk * (rep + 1)
        elif op == 3:
            common = cnt
            custom, pos = _arg(buf, pos); rep, pos = _arg(buf, pos)
            c = buf[pos:pos + common]; pos += common
            for _ in range(rep):
                out += c + buf[pos:pos + custom]; pos += custom
            out += c
        elif op == 4:
            common = cnt
            custom, pos = _arg(buf, pos); rep, pos = _arg(buf, pos)
            for _ in range(rep):
                out += bytes(common) + buf[pos:pos + custom]; pos += custom
            out += bytes(common)
        else:
            raise ValueError("bad pattern opcode %d" % op)
    out += bytes(total - len(out))
    return bytes(out)

class PEF:
    def __init__(self, path):
        blob = open(path, "rb").read()
        t1, t2, arch, ver, ts, _, _, _, nsec, ninst, _ = struct.unpack(">4s4s4sIIIIIHHI", blob[:40])
        assert (t1, t2, arch) == (b"Joy!", b"peff", b"pwpc"), "not a PowerPC PEF"
        self.timestamp = datetime.datetime(1904, 1, 1) + datetime.timedelta(seconds=ts)
        self.sections = [Section(i, blob[40 + 28 * i:68 + 28 * i], blob) for i in range(nsec)]
