"""Find .global entries in upstream asm that are not real function starts (IDA split artifacts).

A real start is a traceback-derived function start. Anything else that upstream marked .global
either sits inside a real function (a fake split) or in code that has no traceback table.
With --fix DIR, writes copies of the TUs to DIR with fake splits demoted to plain labels.
"""
import csv, glob, os, re, sys, collections
decomp, syms = sys.argv[1:3]
fix = sys.argv[sys.argv.index("--fix") + 1] if "--fix" in sys.argv else None
F = sorted((int(r["start"], 16), int(r["size"]), r["name"]) for r in csv.DictReader(open(syms)))
starts = {s for s, _, _ in F}
import bisect
st = [s for s, _, _ in F]
def inside(a):
    i = bisect.bisect_right(st, a) - 1
    return F[i] if i >= 0 and a < F[i][0] + F[i][1] else None
addr_rx = re.compile(r"/\* [0-9A-F]{8} ([0-9A-F]{8}) ")
stats = collections.Counter(); victims = collections.Counter(); by_tu = collections.Counter()
for p in sorted(glob.glob(os.path.join(decomp, "asm/code/*.s"))):
    tu = os.path.basename(p)[:-2]
    lines = open(p, encoding="latin-1").read().split("\n")
    out = list(lines)
    renames = {}
    for i, l in enumerate(lines):
        m = re.match(r'\.global "?([^"\s]+)"?\s*$', l)
        if not m: continue
        a = None
        for j in range(i + 1, min(i + 6, len(lines))):
            mm = addr_rx.match(lines[j])
            if mm: a = int(mm.group(1), 16); break
        if a is None: continue
        if a in starts: stats["real start"] += 1; continue
        host = inside(a)
        if host:
            stats["fake split inside a real function"] += 1
            victims[host[2]] += 1; by_tu[tu] += 1
            out[i] = "# fake split (inside %s)" % host[2]
            renames[m.group(1)] = "lbl_%08X" % (a + 0x10000000)
        else:
            stats["no traceback (runtime/glue)"] += 1
    if renames:
        # m2c only treats lbl_-style labels as local, so rename each fake piece and its references
        txt = "\n".join(out)
        defined = set(re.findall(r"^(lbl_[0-9A-F]{8}):", txt, re.M))
        for old, new in renames.items():
            q = re.escape(old)
            if new in defined:
                txt = re.sub(r'^"?%s"?:\s*$' % q, "", txt, flags=re.M)
            txt = re.sub(r'(?<![\w.])"?%s"?(?![\w])' % q, new, txt)
        out = txt.split("\n")
    if fix and out != lines:
        os.makedirs(fix, exist_ok=True)
        open(os.path.join(fix, tu + ".s"), "w", encoding="latin-1").write("\n".join(out))
for k, v in stats.most_common(): print("%-36s %6d" % (k, v))
print("real functions cut into pieces: %d, in %d TUs" % (len(victims), len(by_tu)))
for n, k in victims.most_common(8): print("   %3d extra pieces  %s" % (k, n[:80]))
