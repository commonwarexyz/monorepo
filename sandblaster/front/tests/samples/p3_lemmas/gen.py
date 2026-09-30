#!/usr/bin/env python3
"""Generate the pe P3 prelude lemma files from this sample.

Recipe (as for `lemmas/nat.core`, GAPS):
1. temporarily append `self.env.print_def_decl(&d)` of every definition to a
   file in `elab/items.rs::add_definition` (before `env.add_def`);
2. build with `seq_lib.core` and `bits_pow2.core` left out of
   `auto::lemmas::FILES` and `lemmas/nat.core` cut at the marker line below,
   so no generated lemma is used in the proof of itself;
3. `sandblaster check tests/samples/p3_lemmas/mod.rs` (the §15 gate errors of a
   sample crate are expected), then `gen.py DUMP sandblaster/front/lemmas`;
4. undo 1 and 2; `prover_ergonomics_p3::p3_lemmas_match_their_source` checks
   that the source still proves exactly the files' statements.

The script turns the dump into core text:

* `seq.rs`, `view.rs`, `option.rs` -> `lemmas/seq_lib.core`: proved at the
  element types `crate::<module>::E` (and `F`), generalized to leading type
  parameters `T` (and `U`); `E` never occurs in a proof except as the
  element type, and the kernel re-checks the generalized terms when the
  file is loaded, so a wrong generalization cannot load;
* `nat.rs` -> the second part of `lemmas/nat.core` (after the marker line);
* `shift.rs` -> `lemmas/bits_pow2.core`.

usage: gen.py DUMP LEMMAS_DIR
"""
import re, sys, os
dump, lemdir = sys.argv[1:3]
here = os.path.dirname(os.path.abspath(__file__))
defs = [d.strip() for d in open(dump).read().split('\n\n') if d.strip()]
defs = [d for d in defs if d.startswith('def[lemma] crate::')]
by = {}
for d in defs:
    path = d.split()[1].split('::')
    by[(path[1], path[2])] = d
NS = {'seq': 'seq', 'view': 'slice', 'option': 'option', 'nat': 'nat', 'shift': 'bits'}

def docs_of(mod):
    """Lemma names in source order with the first line of their doc comment."""
    src = open(os.path.join(here, mod + '.rs')).read()
    out = []
    for m in re.finditer(r'((?:/// .*\n)+)#\[lemma\]\n(?:#\[.*\]\n)*fn ([a-z_0-9]+)', src):
        doc = ' '.join(l[4:] for l in m.group(1).splitlines())
        out.append((m.group(2), doc))
    return out

def gen(mod):
    E, F = f'crate::{mod}::E', f'crate::{mod}::F'
    names = docs_of(mod)
    # the type parameters a lemma needs: `T` for `E`, then `U` for `F`
    tparams = {n: [p for p, x in (('T', E), ('U', F)) if x in by[(mod, n)]] for n, _ in names}
    text = []
    def fix(s):
        def rep(m):
            if m.group(0) in (E, F):
                return m.group(0)
            ns = NS[m.group(1)]
            extra = ''.join(' ' + p for p in tparams.get(m.group(2), [])) if m.group(1) == mod else ''
            return f'{ns}::{m.group(2)}' + extra
        s = re.sub(r'crate::([a-z_0-9]+)::([A-Za-z_0-9]+)', rep, s)
        return s.replace(E, 'T').replace(F, 'U')
    for n, doc in names:
        d = by[(mod, n)]
        _, _, rest = d.partition(' : ')
        ty, _, body = rest.partition(' := ')
        ty, body = fix(ty), fix(body)
        ps = tparams[n]
        if ps:
            binders = ''.join(f'({p} : Type) ' for p in ps)
            ty = binders + ty
            assert body.startswith('fun ('), n
            body = 'fun ' + binders + body[4:]
            body = body.replace('rec(', 'rec(' + ''.join(p + ', ' for p in ps))
            body = re.sub(r' structural (\d+)$', lambda m: f' structural {int(m.group(1)) + len(ps)}', body)
        text.append(f'-- {doc}\ndef[lemma] {NS[mod]}::{n} : {ty} :=\n  {body}\n')
    return '\n'.join(text)

HEAD = open(os.path.join(here, 'headers.txt')).read().split('%%\n')
seq = HEAD[0] + '\n' + gen('seq') + '\n' + HEAD[3] + '\n' + gen('view') + '\n' + HEAD[4] + '\n' + gen('option')
open(os.path.join(lemdir, 'seq_lib.core'), 'w').write(seq)
bits = HEAD[1] + '\n' + gen('shift')
open(os.path.join(lemdir, 'bits_pow2.core'), 'w').write(bits)
natp = os.path.join(lemdir, 'nat.core')
old = open(natp).read()
marker = '-- ---- pe P3: generated from tests/samples/p3_lemmas/nat.rs ----\n'
old = old.split(marker)[0].rstrip('\n') + '\n\n'
open(natp, 'w').write(old + marker + HEAD[2] + '\n' + gen('nat'))
print('ok')
