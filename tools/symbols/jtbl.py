"""Make CodeWarrior/CFM switch jump tables visible to m2c.

CFM dispatch is a double indirection:
    cmplwi rN, MAX ; bgt default
    lwz   rT, SLOT-_R2_BASE_(r2)    # TOC slot holds a pointer to the table
    slwi  rN, rN, 2 ; lwzx rT, rT, rN ; mtctr rT ; bctr
The TOC slot and the table both live in upstream's data.s with relocated pointer values.
This rewrites the slot load into a direct `lis/addi jtbl_XXXXXXXX` and appends the table
as a .rodata block of `.4byte lbl_...` entries, so m2c's jump-table detection works.
Draft-only: the rewrite changes instruction count, so it is not for matching.

usage: jtbl.py DECOMP_DATA_S ASM_DIR TU [TU ...]   (rewrites ASM_DIR/TU.s in place)
"""
import re, sys, os, collections
data_s, asm_dir = sys.argv[1:3]; tus = sys.argv[3:]
word = {}                         # address -> ("lbl_XXXXXXXX" | raw int)
cur = None
for line in open(data_s, encoding="latin-1"):
    m = re.match(r"\s*# ROM: 0x([0-9A-F]+)", line)
    if m: cur = int(m.group(1), 16) + 0x10000000; continue
    m = re.match(r'\s*\.4byte\s+(\S+?)\s*(?:;#\s*ptr\s*\(0x([0-9A-F]+)\))?\s*$', line)
    if m and cur is not None:
        word[cur] = int(m.group(2), 16) if m.group(2) else None
        cur += 4
addr_rx = re.compile(r"/\* ([0-9A-F]{8}) [0-9A-F]{8}  (?:[0-9A-F]{2} ){4}\*/\t(.*)$")
stats = collections.Counter()
for tu in tus:
    p = os.path.join(asm_dir, tu + ".s")
    L = open(p, encoding="latin-1").read().split("\n")
    defined = set(re.findall(r"^(lbl_[0-9A-F]{8}):", "\n".join(L), re.M))
    tables = {}; need_labels = set()
    for i, l in enumerate(L):
        if not l.endswith("bctr "): continue
        stats["bctr"] += 1
        # anchor on data flow: lwzx rT, rB, rN ; mtctr rT ; bctr  ->  rB came from the TOC slot load
        cmp_ = slot = slot_line = None
        base = None
        for j in range(i - 1, max(0, i - 4), -1):
            m = addr_rx.match(L[j])
            mm = m and re.match(r"lwzx r\d+, (r\d+), r\d+", m.group(2))
            if mm: base = mm.group(1); lwzx_line = j; break
        if base:
            for j in range(lwzx_line - 1, max(0, lwzx_line - 24), -1):
                m = addr_rx.match(L[j])
                mm = m and re.match(r"lwz %s, lbl_([0-9A-F]{8})-_R2_BASE_\(r2\)" % base, m.group(2))
                if mm: slot = (base, int(mm.group(1), 16)); slot_line = j; break
        if slot:
            for j in range(slot_line, max(0, slot_line - 24), -1):
                m = addr_rx.match(L[j])
                mm = m and re.match(r"cmplwi r\d+, (0x[0-9a-fA-F]+|\d+)", m.group(2))
                if mm: cmp_ = int(mm.group(1), 0); break
        if cmp_ is None or slot is None:
            stats["pattern not recognised"] += 1; continue
        tbl = word.get(slot[1])
        if tbl is None:
            stats["slot not a pointer"] += 1; continue
        ents = [word.get(tbl + 4 * k) for k in range(cmp_ + 1)]
        if any(e is None for e in ents):
            stats["table entry not a pointer"] += 1; continue
        name = "jtbl_%08X" % tbl
        tables[name] = ents
        need_labels.update(ents)
        m = addr_rx.match(L[slot_line])
        prefix = L[slot_line][:L[slot_line].index("*/") + 2]
        reg = slot[0]
        L[slot_line] = "%s\tlis %s, %s@ha\n%s\taddi %s, %s, %s@l" % (prefix, reg, name, prefix, reg, reg, name)
        stats["tables resolved"] += 1
    # every target must exist as a label in this file
    missing = {e for e in need_labels if "lbl_%08X" % e not in defined}
    if missing:
        for i, l in enumerate(L):
            m = re.match(r"/\* ([0-9A-F]{8}) ", l)
            if m and int(m.group(1), 16) in missing:
                L[i] = "lbl_%s:\n%s" % (m.group(1), l); missing.discard(int(m.group(1), 16))
        stats["labels added"] += 0
    if missing: stats["targets outside file"] += len(missing)
    if tables:
        L.append('\n.section .rodata, "a"')
        for name, ents in sorted(tables.items()):
            L.append(".global %s\n%s:" % (name, name))
            L += ["\t.4byte lbl_%08X" % e for e in ents]
    open(p, "w", encoding="latin-1").write("\n".join(L))
for k, v in stats.most_common(): print("%-28s %5d" % (k, v))
