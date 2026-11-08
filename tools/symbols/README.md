# symbols

`The Sims Complete.map` is an IDA Pro export, not a CodeWarrior linker map, and it misses ~1,100
small functions. Every CodeWarrior function in the baserom is followed by a traceback table holding its
mangled name and exact length, so `symbols.csv` (repo root) is regenerated straight from the binary:

    python3 tools/symbols/tbscan.py baserom > symbols.csv          # 15,169 functions, no overlaps

`reassemble.py` assembles every `asm/code/*.s` with `powerpc-linux-gnu-as` and checks each listed
instruction against the baserom (relocated words masked): all 478 TUs match.

    python3 tools/symbols/reassemble.py . baserom /path/to/binutils/bin

`callgraph.py` decodes direct `bl`/`b` edges from the baserom (needs a tagged symbol CSV; see the
sims1-port repo for the tagger).
