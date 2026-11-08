"""Assemble every upstream asm/code TU with powerpc-linux-gnu-as and compare .text bytes to the baserom."""
import os, re, subprocess, sys, tempfile, glob, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pef import PEF
decomp, pef_path, bindir = sys.argv[1:4]
code = PEF(pef_path).sections[0].data()
AS = os.path.join(bindir, "powerpc-linux-gnu-as"); OBJCOPY = os.path.join(bindir, "powerpc-linux-gnu-objcopy")
tmp = tempfile.mkdtemp()
res = {"ok": [], "mismatch": [], "asm_error": []}
stats = {"relocs": 0, "bytes": 0}
for p in sorted(glob.glob(os.path.join(decomp, "asm/code/*.s"))):
    tu = os.path.basename(p)[:-2]
    lo = None
    for line in open(p, encoding="latin-1"):
        m = re.match(r"/\* [0-9A-F]{8} ([0-9A-F]{8}) ", line)
        if m: lo = int(m.group(1), 16); break
    o = os.path.join(tmp, tu + ".o"); b = os.path.join(tmp, tu + ".bin")
    r = subprocess.run([AS, "-mregnames", "-mgekko" if False else "-many", "-I", os.path.join(decomp, "asm"), p, "-o", o], capture_output=True, text=True)
    if r.returncode:
        res["asm_error"].append((tu, r.stderr.strip().splitlines()[0] if r.stderr else "")); continue
    # TU files use custom section names (.text0 etc); dump all alloc+code sections in order
    subprocess.run([OBJCOPY, "-O", "binary", "--only-section=.text*", o, b], check=True)
    got = bytearray(open(b, "rb").read())
    # the .s lists one instruction per commented line, in order; rebuild the expected
    # stream from the baserom at each listed address (traceback tables are not in the .s)
    addrs = [int(m.group(1), 16) for m in re.finditer(r"/\* [0-9A-F]{8} ([0-9A-F]{8}) ", open(p, encoding="latin-1").read())]
    want = bytearray(b"".join(code[a:a+4] for a in addrs))
    if len(want) != len(got):
        res["mismatch"].append((tu, "len", len(got), len(want))); continue
    # mask words touched by relocations (unlinked external branches / address loads)
    rel = subprocess.run([os.path.join(bindir, "powerpc-linux-gnu-readelf"), "-rW", o], capture_output=True, text=True).stdout
    nrel = 0
    for m in re.finditer(r"^([0-9a-f]{8})\s+[0-9a-f]+\s+(R_PPC_\w+)", rel, re.M):
        off = int(m.group(1), 16) & ~3
        got[off:off+4] = want[off:off+4] = b"\0\0\0\0"; nrel += 1
    stats["relocs"] += nrel; stats["bytes"] += len(got)
    if got == want: res["ok"].append(tu)
    else:
        i = next((i for i in range(min(len(got), len(want))) if got[i] != want[i]), -1)
        res["mismatch"].append((tu, hex(addrs[i // 4]), got[i//4*4:i//4*4+4].hex(), want[i//4*4:i//4*4+4].hex()))
print("bytes compared %d, relocated words masked %d" % (stats["bytes"], stats["relocs"]))
print("assembled+matched %d, mismatched %d, assembler errors %d" % (len(res["ok"]), len(res["mismatch"]), len(res["asm_error"])))
for k in ("mismatch", "asm_error"):
    for x in res[k][:6]: print("  ", k, x)
    if k == "asm_error":
        for tu, _ in res[k]: print(subprocess.run([AS, "-many", "-I", os.path.join(decomp, "asm"), os.path.join(decomp, "asm/code", tu + ".s"), "-o", "/dev/null"], capture_output=True, text=True).stderr[:600])
