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

## Fake function splits (fixed in asm/code)

The asm split followed IDA's function boundaries, which cut 179 real functions into 286 extra
pieces (`sub_XXXXXXXX` / `nullsub_*` globals in the middle of a function, usually at switch-case
targets). Among them are core SimAntics primitives such as `cXObject::InterpValue`,
`TryGenericSimCall`, `TryInventoryAction` and `TryCreateObject`; they can't be decompiled or
matched while split. `fake_splits.py` finds every `.global` that isn't a traceback function
start and demotes it to a local `lbl_` label. Reassembly is still byte-exact for all 478 TUs.

    python3 tools/symbols/fake_splits.py . symbols.csv               # report
    python3 tools/symbols/fake_splits.py . symbols.csv --fix asm/code

## m2c

m2c (`-t ppc-mwcc-c++`) needs two preparations on a *copy* of the asm (drafting only, not matching):
rewrite TOC accesses `sym-_R2_BASE_(r2)` / `addi rX, r2, sym-_R2_BASE_` to `@sda21`, and run
`jtbl.py asm/data/data.s COPYDIR TU...` to turn CFM's TOC-slot jump tables into `jtbl_` tables m2c
can follow. With both, m2c drafts 5,996 of 5,999 functions in the sim/content/core/animation TUs.
