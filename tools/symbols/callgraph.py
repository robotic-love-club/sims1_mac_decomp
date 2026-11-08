"""Direct-call graph from the baserom: decode every bl/b in every recovered function.

Indirect calls (vtables, function pointers) are not visible here; COM and virtual
dispatch are undercounted. Writes:
  data/callgraph_edges.csv       caller,callee,kind,count  (kind: call|tail)
  data/callgraph_subsystems.csv  caller_subsystem,callee_subsystem,edges,callsites
  data/callgraph_tu.dot          TU-level graph (edges with >=3 call sites)
and prints what a headless sim build would have to link or stub.
"""
import csv, os, sys, bisect, collections, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pef import PEF
pef_path, tagged, mapfile, outdir = sys.argv[1:5]
code = PEF(pef_path).sections[0].data()
F = [(int(r["start"], 16), int(r["size"]), r["tu"], r["subsystem"], r["mangled"]) for r in csv.DictReader(open(tagged))]
starts = [f[0] for f in F]
glue = {}
for line in open(mapfile, encoding="latin-1"):
    m = re.match(r"\s*0001:(005[89AB][0-9A-F]{4})\s+\.([A-Za-z_]\w*)\s*$", line)
    if m: glue[int(m.group(1), 16)] = m.group(2)

def owner(a):
    i = bisect.bisect_right(starts, a) - 1
    if i >= 0 and a < F[i][0] + F[i][1]: return i
    return None

edges = collections.Counter()
imports = collections.Counter()
for ci, (s, sz, tu, sub, name) in enumerate(F):
    for a in range(s, s + sz, 4):
        w, = struct.unpack(">I", code[a:a+4])
        if w >> 26 != 18 or w & 2:      # I-form branch, relative only
            continue
        li = w & 0x03FFFFFC
        if li & 0x02000000: li -= 0x04000000
        t = a + li; lk = w & 1
        ti = owner(t)
        if ti is None:
            if lk and t in glue: imports[(ci, glue[t])] += 1
            continue
        if ti == ci: continue          # intra-function branch
        if not lk and t != F[ti][0]: continue
        edges[(ci, ti, "call" if lk else "tail")] += 1

os.makedirs(outdir, exist_ok=True)
with open(os.path.join(outdir, "callgraph_edges.csv"), "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n"); w.writerow(["caller", "callee", "kind", "count"])
    for (a, b, k), n in sorted(edges.items()): w.writerow([F[a][4], F[b][4], k, n])
    for (a, imp), n in sorted(imports.items()): w.writerow([F[a][4], "import:" + imp, "call", n])
sub = collections.Counter(); subn = collections.Counter()
tu = collections.Counter()
for (a, b, k), n in edges.items():
    sub[(F[a][3], F[b][3])] += n; subn[(F[a][3], F[b][3])] += 1
    if F[a][2] != F[b][2]: tu[(F[a][2], F[b][2])] += n
with open(os.path.join(outdir, "callgraph_subsystems.csv"), "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n"); w.writerow(["caller_subsystem", "callee_subsystem", "edges", "callsites"])
    for k, n in sorted(sub.items(), key=lambda kv: -kv[1]): w.writerow([k[0], k[1], subn[k], n])
with open(os.path.join(outdir, "callgraph_tu.dot"), "w") as f:
    f.write("digraph tus {\n  rankdir=LR; node [shape=box,fontsize=9];\n")
    for (a, b), n in tu.items():
        if n >= 3: f.write('  "%s" -> "%s" [weight=%d];\n' % (a, b, n))
    f.write("}\n")
print("functions %d, direct edges %d, call sites %d, import call sites %d" % (len(F), len(edges), sum(edges.values()), sum(imports.values())))
reached = {a for a, b, k in edges} | {b for a, b, k in edges}
print("functions with no direct callers or callees (likely virtual-only): %d" % (len(F) - len(reached)))

# headless closure: start from sim/content/core, follow direct calls everywhere
HEAD = ("sim", "content", "core")
adj = collections.defaultdict(set)
for a, b, k in edges: adj[a].add(b)
seed = [i for i, f in enumerate(F) if f[3].startswith(HEAD)]
seen = set(seed); st = list(seed)
while st:
    x = st.pop()
    for y in adj[x]:
        if y not in seen: seen.add(y); st.append(y)
need = collections.Counter(); needb = collections.Counter()
for i in seen:
    need[F[i][3]] += 1; needb[F[i][3]] += F[i][1]
print("\nheadless sim seed: %d functions; transitive direct-call closure: %d functions, %d instructions" % (len(seed), len(seen), sum(F[i][1] for i in seen) // 4))
for k, v in needb.most_common(): print("   %-36s %5d funcs %7d instr" % (k, need[k], v // 4))
print("\nsubsystem -> subsystem call sites (top 20, excluding self and msl)")
for (a, b), n in sub.most_common():
    if a == b or "msl" in a or "msl" in b: continue
    print("   %-34s -> %-34s %5d" % (a, b, n)); 
    if (n < 60): break
