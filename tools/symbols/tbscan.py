"""Recover every function from CodeWarrior/AIX traceback tables in a PEF code section.

Each compiled function is followed by a zero word and a traceback table. When
has_tboff is set the table records the function length; when name_present is set
it records the (mangled) name. Together these give start, size and name for every
function without relying on a disassembler's heuristics.
"""
import struct, sys, csv, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pef import PEF

BRANCH_ENDS = {0x4E800020, 0x4E800420}  # blr, bctr

def scan(code):
    out = []
    n = len(code)
    pos = 4
    while pos + 12 <= n:
        if code[pos:pos+4] != b"\0\0\0\0":
            pos += 4; continue
        ver, lang, f1, f2, f3, f4, fixedp, f5 = code[pos+4:pos+12]
        has_tboff = f1 & 0x20; int_hndl = f2 & 0x80; name_present = f2 & 0x40
        has_ctl = f1 & 0x08; uses_alloca = f2 & 0x20
        if ver != 0 or lang > 0x0F or not has_tboff:
            pos += 4; continue
        p = pos + 12
        floatp = f5 >> 1
        if fixedp or floatp:
            p += 4
        tboff, = struct.unpack(">I", code[p:p+4]); p += 4
        start = pos - tboff
        if tboff == 0 or tboff & 3 or start < 0 or tboff > 0x100000:
            pos += 4; continue
        if int_hndl:
            p += 4
        if has_ctl:
            cnt, = struct.unpack(">I", code[p:p+4]); p += 4 + 4 * cnt
            if cnt > 64:
                pos += 4; continue
        name = None
        if name_present:
            ln, = struct.unpack(">H", code[p:p+2]); p += 2
            raw = code[p:p+ln]; p += ln
            if ln == 0 or ln > 1024 or any(c < 0x20 or c > 0x7E for c in raw):
                pos += 4; continue
            name = raw.decode("ascii")
        # Real tables are named, and a function cannot start before the previous
        # function's traceback table ended.
        prev_end = out[-1]["tb_end"] if out else 0
        if name is None or start < prev_end:
            pos += 4; continue
        out.append(dict(start=start, size=tboff, tb=pos, tb_end=p, name=name, lang=lang))
        pos = (p + 3) & ~3
    return out

if __name__ == "__main__":
    code = PEF(sys.argv[1]).sections[0].data()
    fns = scan(code)
    w = csv.writer(sys.stdout, lineterminator="\n")
    w.writerow(["start", "size", "name"])
    for f in fns:
        w.writerow(["%08X" % f["start"], f["size"], f["name"] or ""])
