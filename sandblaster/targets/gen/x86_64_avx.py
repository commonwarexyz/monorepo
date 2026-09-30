#!/usr/bin/env python3
"""Generator of core/x86_64_avx.core (MODELS.md §10) and of the Rust table
entries that must match it.

    python3 gen/x86_64_avx.py core   > core/x86_64_avx.core
    python3 gen/x86_64_avx.py coretext   # `x86!(...)` lines of src/coretext.rs
    python3 gen/x86_64_avx.py registry   # `wide!(...)` lines of src/registry.rs
    python3 gen/x86_64_avx.py hw > src/hw/x86_64_wide.rs   # hardware wrappers + campaign (untrusted)
    python3 gen/x86_64_avx.py consistency   # rows of consistency::x86_wide_model
    python3 gen/x86_64_avx.py kernel   # rows of kernel::crosscheck_part

The generated core text is TRUSTED (TCB item 4, DESIGN.md §1.1) exactly like
the hand-written core/x86_64.core: review the output, not only this script.
The script exists because the 256/512-bit helpers are fully unrolled (64-lane
constructors, views, maps) and writing them by hand invites slips; the model
bodies are one or a few lines each and mirror src/x86_64/{vec,avx512,avx2,
ifma,gfni,vbmi}.rs. Every model is cross-checked against its executable model
by kernel evaluation (tests/kernel_crosscheck.rs), so a generator bug shows up
as a mismatch or a load failure, never silently.
"""
import sys

# ---------------------------------------------------------------------------
# Model table: (name, source file, features, instruction, immediate name or
# None, params [(name, type)], result type, kind, width in bytes, items after
# the first). Types: 'V64', 'V32', 'V16' (byte vectors), 'U8', 'U16', 'U32',
# 'U64' (words). The order is the registry order.

D = ["X86Wide::dword", "X86Wide::set_dword"]
Q = ["X86Wide::qword", "X86Wide::set_qword"]
F = ["avx512f"]
VL = ["avx512f", "avx512vl"]
TY = {64: "X86Wide::M512i", 32: "X86Wide::M256i", 16: "X86Mod::M128i"}

MODELS = []


U32_IMM = {"_mm512_slli_epi32", "_mm512_srli_epi32", "_mm512_slli_epi64", "_mm512_srli_epi64"}


def m(name, src, feats, instr, imm, params, ret, kind, width, items, **kw):
    MODELS.append(dict(name=name, src=src, feats=feats, instr=instr, imm=imm, params=params, ret=ret, kind=kind,
                       width=width, items=items, consty="u32" if name in U32_IMM else "i32", **kw))


def V(n):
    return f"V{n}"


def bin_(name, src, feats, instr, width, op, lane, items):
    m(name, src, feats, instr, None, [("a", V(width)), ("b", V(width))], V(width), "map2", width, items + [TY[width]],
      op=op, lane=lane)


# A. AVX-512F/BW/DQ, 512-bit
m("_mm512_loadu_si512", "Avx512", F, "VMOVDQU32 zmm1, m512", None, [("mem", "V64")], "V64", "copy", 64,
  ["X86Vec::vmovdqu", TY[64]])
m("_mm512_storeu_si512", "Avx512", F, "VMOVDQU32 m512, zmm1", None, [("a", "V64")], "V64", "copy", 64,
  ["X86Vec::vmovdqu", TY[64]])
bin_("_mm512_add_epi32", "Avx512", F, "VPADDD zmm1, zmm2, zmm3/m512", 64, "#wadd_u32(x, y)", "u32", ["X86Vec::vpaddd"] + D)
bin_("_mm512_add_epi64", "Avx512", F, "VPADDQ zmm1, zmm2, zmm3/m512", 64, "#wadd_u64(x, y)", "u64", ["X86Vec::vpaddq"] + Q)
bin_("_mm512_sub_epi32", "Avx512", F, "VPSUBD zmm1, zmm2, zmm3/m512", 64, "#wsub_u32(x, y)", "u32", ["X86Vec::vpsubd"] + D)
bin_("_mm512_sub_epi64", "Avx512", F, "VPSUBQ zmm1, zmm2, zmm3/m512", 64, "#wsub_u64(x, y)", "u64", ["X86Vec::vpsubq"] + Q)
bin_("_mm512_xor_si512", "Avx512", F, "VPXORD zmm1, zmm2, zmm3/m512", 64, "#xor_u32(x, y)", "u32", ["X86Vec::vpxord"] + D)
bin_("_mm512_and_si512", "Avx512", F, "VPANDD zmm1, zmm2, zmm3/m512", 64, "#and_u32(x, y)", "u32", ["X86Vec::vpandd"] + D)
bin_("_mm512_or_si512", "Avx512", F, "VPORD zmm1, zmm2, zmm3/m512", 64, "#or_u32(x, y)", "u32", ["X86Vec::vpord"] + D)
bin_("_mm512_andnot_si512", "Avx512", F, "VPANDND zmm1, zmm2, zmm3/m512", 64, "#and_u32(#not_u32(x), y)", "u32",
     ["X86Vec::vpandnd"] + D)


def tern(name, feats, instr, width, lane, items):
    m(name, "Avx512", feats, instr, "IMM8", [("a", V(width)), ("b", V(width)), ("c", V(width))], V(width), "ternlog",
      width, items + [TY[width]], lane=lane)


tern("_mm512_ternarylogic_epi32", F, "VPTERNLOGD zmm1, zmm2, zmm3/m512, imm8", 64, "u32", ["X86Vec::vpternlogd"] + D)
tern("_mm512_ternarylogic_epi64", F, "VPTERNLOGQ zmm1, zmm2, zmm3/m512, imm8", 64, "u64", ["X86Vec::vpternlogq"] + Q)


def unimm(name, src, feats, instr, width, lane, op, items):
    """A lanewise unary operation with an immediate `IMM8` (op over `x`)."""
    m(name, src, feats, instr, "IMM8", [("a", V(width))], V(width), "map1", width, items + [TY[width]], lane=lane, op=op)


ROT = {
    "rol32": "#rotl_u32(x, #and_u32(IMM8, 31u32))",
    "ror32": "#rotr_u32(x, #and_u32(IMM8, 31u32))",
    "rol64": "#rotl_u64(x, #and_u32(IMM8, 63u32))",
    "ror64": "#rotr_u64(x, #and_u32(IMM8, 63u32))",
}
unimm("_mm512_rol_epi32", "Avx512", F, "VPROLD zmm1, zmm2/m512, imm8", 64, "u32", ROT["rol32"],
      ["X86Vec::vprold", "X86Vec::left_rotate_dwords"] + D)
unimm("_mm512_ror_epi32", "Avx512", F, "VPRORD zmm1, zmm2/m512, imm8", 64, "u32", ROT["ror32"],
      ["X86Vec::vprord", "X86Vec::right_rotate_dwords"] + D)
unimm("_mm512_rol_epi64", "Avx512", F, "VPROLQ zmm1, zmm2/m512, imm8", 64, "u64", ROT["rol64"],
      ["X86Vec::vprolq", "X86Vec::left_rotate_qwords"] + Q)
unimm("_mm512_ror_epi64", "Avx512", F, "VPRORQ zmm1, zmm2/m512, imm8", 64, "u64", ROT["ror64"],
      ["X86Vec::vprorq", "X86Vec::right_rotate_qwords"] + Q)
bin_("_mm512_rolv_epi32", "Avx512", F, "VPROLVD zmm1, zmm2, zmm3/m512", 64, "#rotl_u32(x, #and_u32(y, 31u32))", "u32",
     ["X86Vec::vprolvd", "X86Vec::left_rotate_dwords"] + D)
bin_("_mm512_rorv_epi32", "Avx512", F, "VPRORVD zmm1, zmm2, zmm3/m512", 64, "#rotr_u32(x, #and_u32(y, 31u32))", "u32",
     ["X86Vec::vprorvd", "X86Vec::right_rotate_dwords"] + D)
bin_("_mm512_rolv_epi64", "Avx512", F, "VPROLVQ zmm1, zmm2, zmm3/m512", 64,
     "#rotl_u64(x, #cast_u64_u32(#and_u64(y, 63u64)))", "u64", ["X86Vec::vprolvq", "X86Vec::left_rotate_qwords"] + Q)
bin_("_mm512_rorv_epi64", "Avx512", F, "VPRORVQ zmm1, zmm2, zmm3/m512", 64,
     "#rotr_u64(x, #cast_u64_u32(#and_u64(y, 63u64)))", "u64", ["X86Vec::vprorvq", "X86Vec::right_rotate_qwords"] + Q)
SHI = {
    "sll32": "if #le_u32(IMM8, 31u32) return U32 then #wshl_u32(x, IMM8) else 0u32",
    "srl32": "if #le_u32(IMM8, 31u32) return U32 then #wshr_u32(x, IMM8) else 0u32",
    "sll64": "if #le_u32(IMM8, 63u32) return U64 then #wshl_u64(x, IMM8) else 0u64",
    "srl64": "if #le_u32(IMM8, 63u32) return U64 then #wshr_u64(x, IMM8) else 0u64",
}
unimm("_mm512_slli_epi32", "Avx512", F, "VPSLLD zmm1, zmm2/m512, imm8", 64, "u32", SHI["sll32"],
      ["X86Vec::vpslld_imm", "X86Vec::logical_left_shift_dwords1"] + D)
unimm("_mm512_srli_epi32", "Avx512", F, "VPSRLD zmm1, zmm2/m512, imm8", 64, "u32", SHI["srl32"],
      ["X86Vec::vpsrld_imm", "X86Vec::logical_right_shift_dwords1"] + D)
unimm("_mm512_slli_epi64", "Avx512", F, "VPSLLQ zmm1, zmm2/m512, imm8", 64, "u64", SHI["sll64"],
      ["X86Vec::vpsllq_imm", "X86Vec::logical_left_shift_qwords1"] + Q)
unimm("_mm512_srli_epi64", "Avx512", F, "VPSRLQ zmm1, zmm2/m512, imm8", 64, "u64", SHI["srl64"],
      ["X86Vec::vpsrlq_imm", "X86Vec::logical_right_shift_qwords1"] + Q)
m("_mm512_sllv_epi64", "Avx512", F, "VPSLLVQ zmm1, zmm2, zmm3/m512", None, [("a", "V64"), ("count", "V64")], "V64",
  "map2", 64, ["X86Vec::vpsllvq"] + Q + [TY[64]], lane="u64",
  op="if #lt_u64(y, 64u64) return U64 then #wshl_u64(x, #cast_u64_u32(y)) else 0u64")
m("_mm512_srlv_epi64", "Avx512", F, "VPSRLVQ zmm1, zmm2, zmm3/m512", None, [("a", "V64"), ("count", "V64")], "V64",
  "map2", 64, ["X86Vec::vpsrlvq"] + Q + [TY[64]], lane="u64",
  op="if #lt_u64(y, 64u64) return U64 then #wshr_u64(x, #cast_u64_u32(y)) else 0u64")
m("_mm512_shuffle_epi8", "Avx512", ["avx512bw"], "VPSHUFB zmm1, zmm2, zmm3/m512", None, [("a", "V64"), ("b", "V64")],
  "V64", "pshufb", 64, ["X86Vec::vpshufb", TY[64]])
m("_mm512_permutexvar_epi32", "Avx512", F, "VPERMD zmm1, zmm2, zmm3/m512", None, [("idx", "V64"), ("a", "V64")], "V64",
  "permvar", 64, ["X86Vec::vpermd"] + D + [TY[64]], lane="u32", table="a", index="idx")
m("_mm512_permutexvar_epi64", "Avx512", F, "VPERMQ zmm1, zmm2, zmm3/m512", None, [("idx", "V64"), ("a", "V64")], "V64",
  "permvar", 64, ["X86Vec::vpermq"] + Q + [TY[64]], lane="u64", table="a", index="idx")
m("_mm512_permutex2var_epi64", "Avx512", F, "VPERMI2Q zmm1, zmm2, zmm3/m512 (or VPERMT2Q)", None,
  [("a", "V64"), ("idx", "V64"), ("b", "V64")], "V64", "perm2var", 64, ["X86Vec::vpermi2q"] + Q + [TY[64]], lane="u64")
m("_mm512_shuffle_i32x4", "Avx512", F, "VSHUFI32X4 zmm1, zmm2, zmm3/m512, imm8", "MASK", [("a", "V64"), ("b", "V64")],
  "V64", "shuf128", 64, ["X86Vec::vshufi32x4", "X86Vec::vshuf128x4_tmp", "X86Vec::select4"] + D + [TY[64]])
m("_mm512_shuffle_i64x2", "Avx512", F, "VSHUFI64X2 zmm1, zmm2, zmm3/m512, imm8", "MASK", [("a", "V64"), ("b", "V64")],
  "V64", "shuf128", 64, ["X86Vec::vshufi64x2", "X86Vec::vshuf128x4_tmp", "X86Vec::select4"] + Q + [TY[64]])
for nm, ins, lane, hi, it in [
    ("_mm512_unpacklo_epi32", "VPUNPCKLDQ", "u32", False, ["X86Vec::vpunpckldq"] + D),
    ("_mm512_unpackhi_epi32", "VPUNPCKHDQ", "u32", True, ["X86Vec::vpunpckhdq"] + D),
    ("_mm512_unpacklo_epi64", "VPUNPCKLQDQ", "u64", False, ["X86Vec::vpunpcklqdq"] + Q),
    ("_mm512_unpackhi_epi64", "VPUNPCKHQDQ", "u64", True, ["X86Vec::vpunpckhqdq"] + Q),
]:
    m(nm, "Avx512", F, f"{ins} zmm1, zmm2, zmm3/m512", None, [("a", "V64"), ("b", "V64")], "V64", "unpack", 64,
      it + [TY[64]], lane=lane, hi=hi)
m("_mm512_set1_epi32", "Avx512", F, "(composite: VPBROADCASTD zmm1, r32)", None, [("a", "U32")], "V64", "splat", 64,
  ["X86Vec::vpbroadcastd", "X86Wide::set_dword", TY[64]], lane="u32")
m("_mm512_set1_epi64", "Avx512", F, "(composite: VPBROADCASTQ zmm1, r64)", None, [("a", "U64")], "V64", "splat", 64,
  ["X86Vec::vpbroadcastq", "X86Wide::set_qword", TY[64]], lane="u64")
m("_mm512_mask_blend_epi32", "Avx512", F, "VPBLENDMD zmm1 {k1}, zmm2, zmm3/m512", None,
  [("k", "U16"), ("a", "V64"), ("b", "V64")], "V64", "blendm", 64,
  ["X86Vec::vpblendmd", "X86Wide::mask_bit"] + D + [TY[64], "X86Wide::Mmask16"], lane="u32")
m("_mm512_mask_blend_epi64", "Avx512", F, "VPBLENDMQ zmm1 {k1}, zmm2, zmm3/m512", None,
  [("k", "U8"), ("a", "V64"), ("b", "V64")], "V64", "blendm", 64,
  ["X86Vec::vpblendmq", "X86Wide::mask_bit"] + Q + [TY[64], "X86Wide::Mmask8"], lane="u64")
m("_mm512_cmplt_epu64_mask", "Avx512", F, "VPCMPUQ k1, zmm2, zmm3/m512, 1", None, [("a", "V64"), ("b", "V64")], "U8",
  "cmp", 64, ["X86Vec::vpcmpuq_lt", "X86Wide::qword", TY[64], "X86Wide::Mmask8"], lane="u64", cmp="lt")
m("_mm512_cmpeq_epi64_mask", "Avx512", F, "VPCMPEQQ k1, zmm2, zmm3/m512", None, [("a", "V64"), ("b", "V64")], "U8",
  "cmp", 64, ["X86Vec::vpcmpeqq", "X86Wide::qword", TY[64], "X86Wide::Mmask8"], lane="u64", cmp="eq")
m("_mm512_cmpeq_epi32_mask", "Avx512", F, "VPCMPEQD k1, zmm2, zmm3/m512", None, [("a", "V64"), ("b", "V64")], "U16",
  "cmp", 64, ["X86Vec::vpcmpeqd", "X86Wide::dword", TY[64], "X86Wide::Mmask16"], lane="u32", cmp="eq")
m("_mm512_maskz_mov_epi32", "Avx512", F, "VMOVDQA32 zmm1 {k1}{z}, zmm2", None, [("k", "U16"), ("a", "V64")], "V64",
  "maskz", 64, ["X86Vec::vmovdqa32_masked", "X86Wide::mask_bit"] + D + [TY[64], "X86Wide::Mmask16"], lane="u32")
m("_mm512_mask_mov_epi32", "Avx512", F, "VMOVDQA32 zmm1 {k1}, zmm2", None, [("src", "V64"), ("k", "U16"), ("a", "V64")],
  "V64", "maskm", 64, ["X86Vec::vmovdqa32_masked", "X86Wide::mask_bit"] + D + [TY[64], "X86Wide::Mmask16"], lane="u32")
m("_mm512_maskz_mov_epi64", "Avx512", F, "VMOVDQA64 zmm1 {k1}{z}, zmm2", None, [("k", "U8"), ("a", "V64")], "V64",
  "maskz", 64, ["X86Vec::vmovdqa64_masked", "X86Wide::mask_bit"] + Q + [TY[64], "X86Wide::Mmask8"], lane="u64")
m("_mm512_mask_mov_epi64", "Avx512", F, "VMOVDQA64 zmm1 {k1}, zmm2", None, [("src", "V64"), ("k", "U8"), ("a", "V64")],
  "V64", "maskm", 64, ["X86Vec::vmovdqa64_masked", "X86Wide::mask_bit"] + Q + [TY[64], "X86Wide::Mmask8"], lane="u64")
bin_("_mm512_mullo_epi64", "Avx512", ["avx512dq"], "VPMULLQ zmm1, zmm2, zmm3/m512", 64, "#wmul_u64(x, y)", "u64",
     ["X86Vec::vpmullq"] + Q)
bin_("_mm512_mul_epu32", "Avx512", F, "VPMULUDQ zmm1, zmm2, zmm3/m512", 64,
     "#wmul_u64(#and_u64(x, 4294967295u64), #and_u64(y, 4294967295u64))", "u64",
     ["X86Vec::vpmuludq", "X86Wide::dword", "X86Wide::set_qword"])
# A. VL (EVEX.256)
tern("_mm256_ternarylogic_epi32", VL, "VPTERNLOGD ymm1, ymm2, ymm3/m256, imm8", 32, "u32", ["X86Vec::vpternlogd"] + D)
tern("_mm256_ternarylogic_epi64", VL, "VPTERNLOGQ ymm1, ymm2, ymm3/m256, imm8", 32, "u64", ["X86Vec::vpternlogq"] + Q)
unimm("_mm256_rol_epi32", "Avx512", VL, "VPROLD ymm1, ymm2/m256, imm8", 32, "u32", ROT["rol32"],
      ["X86Vec::vprold", "X86Vec::left_rotate_dwords"] + D)
unimm("_mm256_ror_epi32", "Avx512", VL, "VPRORD ymm1, ymm2/m256, imm8", 32, "u32", ROT["ror32"],
      ["X86Vec::vprord", "X86Vec::right_rotate_dwords"] + D)
unimm("_mm256_rol_epi64", "Avx512", VL, "VPROLQ ymm1, ymm2/m256, imm8", 32, "u64", ROT["rol64"],
      ["X86Vec::vprolq", "X86Vec::left_rotate_qwords"] + Q)
unimm("_mm256_ror_epi64", "Avx512", VL, "VPRORQ ymm1, ymm2/m256, imm8", 32, "u64", ROT["ror64"],
      ["X86Vec::vprorq", "X86Vec::right_rotate_qwords"] + Q)
# B. IFMA
for w, feats, reg in [(64, ["avx512ifma"], "zmm"), (32, ["avx512ifma", "avx512vl"], "ymm")]:
    pre = "_mm512" if w == 64 else "_mm256"
    for lohi in ["lo", "hi"]:
        L = "L" if lohi == "lo" else "H"
        m(f"{pre}_madd52{lohi}_epu64", "Ifma", feats, f"VPMADD52{L}UQ {reg}1, {reg}2, {reg}3/m{w * 8}", None,
          [("a", V(w)), ("b", V(w)), ("c", V(w))], V(w), "map3", w,
          [f"Ifma::vpmadd52{L.lower()}uq"] + Q + [TY[w]], lane="u64", op=f"x86_64::madd52{lohi} x y z")
# C. GFNI
GM = ["Gfni::vgf2p8mulb", "Gfni::gf2p8mul_byte"]
GA = ["Gfni::vgf2p8affineqb", "Gfni::affine_byte", "Gfni::parity", "X86Wide::qword"]
GI = ["Gfni::vgf2p8affineinvqb", "Gfni::affine_inverse_byte", "Gfni::inverse", "Gfni::gf2p8mul_byte", "Gfni::parity",
      "X86Wide::qword"]
GF = {64: (["gfni", "avx512f"], "VGF2P8", "zmm1, zmm2, zmm3/m512", "_mm512"),
      32: (["gfni", "avx"], "VGF2P8", "ymm1, ymm2, ymm3/m256", "_mm256"),
      16: (["gfni"], "GF2P8", "xmm1, xmm2/m128", "_mm")}
for w in [64, 32, 16]:
    feats, ins, ops, pre = GF[w]
    m(f"{pre}_gf2p8mul_epi8", "Gfni", feats, f"{ins}MULB {ops}", None, [("a", V(w)), ("b", V(w))], V(w), "map2", w,
      GM + [TY[w]], lane="u8", op="x86_64::gf2p8mul_byte x y")
for w in [64, 32, 16]:
    feats, ins, ops, pre = GF[w]
    m(f"{pre}_gf2p8affine_epi64_epi8", "Gfni", feats, f"{ins}AFFINEQB {ops}, imm8", "B", [("x", V(w)), ("a", V(w))],
      V(w), "affine", w, GA + [TY[w]], inv=False)
for w in [64, 32, 16]:
    feats, ins, ops, pre = GF[w]
    m(f"{pre}_gf2p8affineinv_epi64_epi8", "Gfni", feats, f"{ins}AFFINEINVQB {ops}, imm8", "B",
      [("x", V(w)), ("a", V(w))], V(w), "affine", w, GI + [TY[w]], inv=True)
# D. VBMI
m("_mm512_permutexvar_epi8", "Vbmi", ["avx512vbmi"], "VPERMB zmm1, zmm2, zmm3/m512", None,
  [("idx", "V64"), ("a", "V64")], "V64", "permvar", 64, ["Vbmi::vpermb", TY[64]], lane="u8", table="a", index="idx")
m("_mm512_permutex2var_epi8", "Vbmi", ["avx512vbmi"], "VPERMI2B zmm1, zmm2, zmm3/m512 (or VPERMT2B)", None,
  [("a", "V64"), ("idx", "V64"), ("b", "V64")], "V64", "perm2var", 64, ["Vbmi::vpermi2b", TY[64]], lane="u8")
m("_mm512_multishift_epi64_epi8", "Vbmi", ["avx512vbmi"], "VPMULTISHIFTQB zmm1, zmm2, zmm3/m512", None,
  [("a", "V64"), ("b", "V64")], "V64", "multishift", 64, ["Vbmi::vpmultishiftqb", "X86Wide::qword", TY[64]])
# E. VBMI2 / VPOPCNTDQ / BITALG
for nm, ins, lane, op, it in [
    ("_mm512_shldv_epi64", "VPSHLDVQ", "u64", "x86_64::shld_u64 x y (#cast_u64_u32(#and_u64(z, 63u64)))",
     ["Vbmi::vpshldvq", "Vbmi::concat_qwords"] + Q),
    ("_mm512_shrdv_epi64", "VPSHRDVQ", "u64", "x86_64::shrd_u64 x y (#cast_u64_u32(#and_u64(z, 63u64)))",
     ["Vbmi::vpshrdvq", "Vbmi::concat_qwords"] + Q),
    ("_mm512_shldv_epi32", "VPSHLDVD", "u32", "x86_64::shld_u32 x y (#and_u32(z, 31u32))",
     ["Vbmi::vpshldvd", "Vbmi::concat_dwords"] + D),
    ("_mm512_shrdv_epi32", "VPSHRDVD", "u32", "x86_64::shrd_u32 x y (#and_u32(z, 31u32))",
     ["Vbmi::vpshrdvd", "Vbmi::concat_dwords"] + D),
]:
    m(nm, "Vbmi", ["avx512vbmi2"], f"{ins} zmm1, zmm2, zmm3/m512", None, [("a", "V64"), ("b", "V64"), ("c", "V64")],
      "V64", "map3", 64, it + [TY[64]], lane=lane, op=op)
m("_mm512_shldi_epi64", "Vbmi", ["avx512vbmi2"], "VPSHLDQ zmm1, zmm2, zmm3/m512, imm8", "IMM8",
  [("a", "V64"), ("b", "V64")], "V64", "map2", 64, ["Vbmi::vpshldq_imm", "Vbmi::concat_qwords"] + Q + [TY[64]],
  lane="u64", op="x86_64::shld_u64 x y (#and_u32(IMM8, 63u32))")
m("_mm512_shldi_epi32", "Vbmi", ["avx512vbmi2"], "VPSHLDD zmm1, zmm2, zmm3/m512, imm8", "IMM8",
  [("a", "V64"), ("b", "V64")], "V64", "map2", 64, ["Vbmi::vpshldd_imm", "Vbmi::concat_dwords"] + D + [TY[64]],
  lane="u32", op="x86_64::shld_u32 x y (#and_u32(IMM8, 31u32))")
m("_mm512_popcnt_epi64", "Vbmi", ["avx512vpopcntdq"], "VPOPCNTQ zmm1, zmm2/m512", None, [("a", "V64")], "V64", "map1",
  64, ["Vbmi::vpopcntq"] + Q + [TY[64]], lane="u64", op="#cast_u32_u64(#count_ones_u64(x))")
m("_mm512_popcnt_epi32", "Vbmi", ["avx512vpopcntdq"], "VPOPCNTD zmm1, zmm2/m512", None, [("a", "V64")], "V64", "map1",
  64, ["Vbmi::vpopcntd"] + D + [TY[64]], lane="u32", op="#count_ones_u32(x)")
m("_mm512_popcnt_epi8", "Vbmi", ["avx512bitalg"], "VPOPCNTB zmm1, zmm2/m512", None, [("a", "V64")], "V64", "map1", 64,
  ["Vbmi::vpopcntb", TY[64]], lane="u8", op="#cast_u32_u8(#count_ones_u8(x))")
m("_mm512_popcnt_epi16", "Vbmi", ["avx512bitalg"], "VPOPCNTW zmm1, zmm2/m512", None, [("a", "V64")], "V64", "map1", 64,
  ["Vbmi::vpopcntw", "X86Wide::word", "X86Wide::set_word", TY[64]], lane="u16", op="#cast_u32_u16(#count_ones_u16(x))")
# F. AVX / AVX2
m("_mm256_loadu_si256", "Avx2", ["avx"], "VMOVDQU ymm1, m256", None, [("mem", "V32")], "V32", "copy", 32,
  ["X86Vec::vmovdqu", TY[32]])
m("_mm256_storeu_si256", "Avx2", ["avx"], "VMOVDQU m256, ymm1", None, [("a", "V32")], "V32", "copy", 32,
  ["X86Vec::vmovdqu", TY[32]])
bin_("_mm256_add_epi32", "Avx2", ["avx2"], "VPADDD ymm1, ymm2, ymm3/m256", 32, "#wadd_u32(x, y)", "u32", ["X86Vec::vpaddd"] + D)
bin_("_mm256_add_epi64", "Avx2", ["avx2"], "VPADDQ ymm1, ymm2, ymm3/m256", 32, "#wadd_u64(x, y)", "u64", ["X86Vec::vpaddq"] + Q)
bin_("_mm256_xor_si256", "Avx2", ["avx2"], "VPXOR ymm1, ymm2, ymm3/m256", 32, "#xor_u32(x, y)", "u32", ["X86Vec::vpxord"] + D)
bin_("_mm256_and_si256", "Avx2", ["avx2"], "VPAND ymm1, ymm2, ymm3/m256", 32, "#and_u32(x, y)", "u32", ["X86Vec::vpandd"] + D)
bin_("_mm256_or_si256", "Avx2", ["avx2"], "VPOR ymm1, ymm2, ymm3/m256", 32, "#or_u32(x, y)", "u32", ["X86Vec::vpord"] + D)
m("_mm256_shuffle_epi8", "Avx2", ["avx2"], "VPSHUFB ymm1, ymm2, ymm3/m256", None, [("a", "V32"), ("b", "V32")], "V32",
  "pshufb", 32, ["X86Vec::vpshufb", TY[32]])
m("_mm256_permutevar8x32_epi32", "Avx2", ["avx2"], "VPERMD ymm1, ymm2, ymm3/m256", None, [("a", "V32"), ("idx", "V32")],
  "V32", "permvar", 32, ["X86Vec::vpermd"] + D + [TY[32]], lane="u32", table="a", index="idx")
unimm("_mm256_slli_epi32", "Avx2", ["avx2"], "VPSLLD ymm1, ymm2, imm8", 32, "u32", SHI["sll32"],
      ["X86Vec::vpslld_imm", "X86Vec::logical_left_shift_dwords1"] + D)
unimm("_mm256_srli_epi32", "Avx2", ["avx2"], "VPSRLD ymm1, ymm2, imm8", 32, "u32", SHI["srl32"],
      ["X86Vec::vpsrld_imm", "X86Vec::logical_right_shift_dwords1"] + D)
unimm("_mm256_slli_epi64", "Avx2", ["avx2"], "VPSLLQ ymm1, ymm2, imm8", 32, "u64", SHI["sll64"],
      ["X86Vec::vpsllq_imm", "X86Vec::logical_left_shift_qwords1"] + Q)
unimm("_mm256_srli_epi64", "Avx2", ["avx2"], "VPSRLQ ymm1, ymm2, imm8", 32, "u64", SHI["srl64"],
      ["X86Vec::vpsrlq_imm", "X86Vec::logical_right_shift_qwords1"] + Q)
m("_mm256_blend_epi32", "Avx2", ["avx2"], "VPBLENDD ymm1, ymm2, ymm3/m256, imm8", "IMM8", [("a", "V32"), ("b", "V32")],
  "V32", "blendimm", 32, ["X86Vec::vpblendd"] + D + [TY[32]], lane="u32")
m("_mm256_alignr_epi8", "Avx2", ["avx2"], "VPALIGNR ymm1, ymm2, ymm3/m256, imm8", "IMM8", [("a", "V32"), ("b", "V32")],
  "V32", "alignr", 32, ["X86Vec::vpalignr256", TY[32]])
m("_mm256_set1_epi32", "Avx2", ["avx"], "(composite: VPBROADCASTD ymm / VMOVD + VPSHUFD)", None, [("a", "U32")], "V32",
  "splat", 32, ["X86Vec::vpbroadcastd", "X86Wide::set_dword", TY[32]], lane="u32")
m("_mm256_set1_epi64x", "Avx2", ["avx"], "(composite: VPBROADCASTQ ymm / VMOVQ + VPUNPCKLQDQ)", None, [("a", "U64")],
  "V32", "splat", 32, ["X86Vec::vpbroadcastq", "X86Wide::set_qword", TY[32]], lane="u64")

# ---------------------------------------------------------------------------
# Core text helpers.

LANE = {"u8": ("U8", 1), "u16": ("U16", 2), "u32": ("U32", 4), "u64": ("U64", 8)}
# Helpers already defined in core/x86_64.core (reused, never redefined).
EXISTING = {"u8x2", "u8x4", "u8x8", "u8x16", "u16x8", "u32x4", "u64x2", "concat_u8x16", "view_u16", "view_u32",
            "view_u64", "from_u16x8", "from_u32x4", "from_u64x2", "map_u8x16", "map2_u8x16", "map2_u32x4",
            "pshufb_byte", "palignr_byte"}

HELPERS = {}  # name -> text (insertion order = emission order)


def vty(n):
    return f"Array U8 {n}usize"


def aty(T, k):
    return f"Array {T} {k}usize"


def ix(T, k, arr, i):
    return f"array::index {T} {k}usize {arr} {i}usize .refl(Bool, true)"


def wrap(items, per_line, indent):
    lines = []
    for i in range(0, len(items), per_line):
        lines.append(indent + " ".join(items[i:i + per_line]))
    return "\n".join(lines)


def need(name):
    """Ensure helper `name` is emitted; return its global name."""
    if name in EXISTING or name in HELPERS:
        return f"x86_64::{name}"
    text = build_helper(name)  # registers its dependencies first
    HELPERS[name] = text
    return f"x86_64::{name}"


def cons_list(T, xs):
    s = f"Nil[{T}]"
    for x in reversed(xs):
        s = f"Cons[{T}]({x}, {s})"
    return s


def build_helper(name):
    import re
    mt = re.fullmatch(r"(u8|u16|u32|u64)x(\d+)", name)
    if mt:  # lane constructor
        l, k = mt.group(1), int(mt.group(2))
        T = LANE[l][0]
        params = [f"(x{i} : {T})" for i in range(k)]
        xs = [f"x{i}" for i in range(k)]
        body_list = cons_list(T, xs)
        return (f"-- `[x0, .., x{k - 1}]` as `{aty(T, k)}`.\n"
                f"def[prelude] x86_64::{name} :\n{wrap([p + ' ->' for p in params], 8, '    ')}\n    {aty(T, k)} :=\n"
                f"  fun\n{wrap(params, 8, '    ')} =>\n"
                f"    pair({aty(T, k)},\n      {body_list},\n      refl(Int, {k}int))\n")
    mt = re.fullmatch(r"view_(u16|u32|u64)x(\d+)", name)
    if mt:  # typed view of a byte vector
        l, k = mt.group(1), int(mt.group(2))
        T, sz = LANE[l]
        n = k * sz
        ctor = need(f"{l}x{k}")
        bctor = need(f"u8x{sz}")
        lets = "\n".join(f"    let v{i} : U8 = {ix('U8', n, 'v', i)};" for i in range(n))
        lanes = [f"({l}::from_le_bytes ({bctor} {' '.join(f'v{sz * j + b}' for b in range(sz))}))" for j in range(k)]
        return (f"-- view_{l}x{k} v [j] = {l}::from_le_bytes [v[{sz}j], .., v[{sz}j+{sz - 1}]] (little-endian lanes).\n"
                f"def[prelude] x86_64::{name} : (v : {vty(n)}) -> {aty(T, k)} :=\n"
                f"  fun (v : {vty(n)}) =>\n{lets}\n    {ctor}\n{wrap(lanes, 1, '      ')}\n")
    mt = re.fullmatch(r"from_(u16|u32|u64)x(\d+)", name)
    if mt:  # inverse of the view
        l, k = mt.group(1), int(mt.group(2))
        T, sz = LANE[l]
        n = k * sz
        ctor = need(f"u8x{n}")
        lets = "\n".join(f"    let l{j} : {T} = {ix(T, k, 'l', j)};" for j in range(k))
        bs = []
        for j in range(k):
            for b in range(sz):
                bs.append(f"(#cast_{l}_u8(l{j}))" if b == 0 else f"(#cast_{l}_u8(#wshr_{l}(l{j}, {8 * b}u32)))")
        return (f"-- Inverse of view_{l}x{k}: byte {sz}j + b is cast_u8(l[j] >> 8b).\n"
                f"def[prelude] x86_64::{name} : (l : {aty(T, k)}) -> {vty(n)} :=\n"
                f"  fun (l : {aty(T, k)}) =>\n{lets}\n    {ctor}\n{wrap(bs, sz if sz > 1 else 8, '      ')}\n")
    mt = re.fullmatch(r"(i?)map([23]?)_(u8|u16|u32|u64)x(\d+)", name)
    if mt:  # lanewise maps; `imap` passes the lane index j as a U32 first
        indexed, arity, l, k = mt.group(1) == "i", int(mt.group(2) or 1), mt.group(3), int(mt.group(4))
        T = LANE[l][0]
        ctor = need(f"{l}x{k}")
        argn = ["a", "b", "c"][:arity]
        fty = ("U32 -> " if indexed else "") + " -> ".join([T] * arity) + f" -> {T}"
        params = f"(f : {fty}) " + " ".join(f"({x} : {aty(T, k)})" for x in argn)
        tele = f"(f : {fty}) -> " + " -> ".join(f"({x} : {aty(T, k)})" for x in argn) + f" -> {aty(T, k)}"
        terms = []
        for j in range(k):
            args = " ".join(f"({ix(T, k, x, j)})" for x in argn)
            terms.append(f"(f {j}u32 {args})" if indexed else f"(f {args})")
        what = ", ".join(f"{x}[j]" for x in argn)
        return (f"-- `r[j] = f({'j, ' if indexed else ''}{what})` for j < {k}.\n"
                f"def[prelude] x86_64::{name} : {tele} :=\n  fun {params} =>\n    {ctor}\n{wrap(terms, 1, '      ')}\n")
    mt = re.fullmatch(r"lanes128_u8x(\d+)", name)
    if mt:  # the 128-bit lanes of a byte vector
        n = int(mt.group(1))
        L = n // 16
        u16 = need("u8x16")
        T = aty("U8", 16)
        lanes = [f"{u16} " + " ".join(f"({ix('U8', n, 'a', 16 * l + b)})" for b in range(16)) for l in range(L)]
        lst = f"Nil[{T}]"
        for x in reversed(lanes):
            lst = f"Cons[{T}]({x},\n        {lst})"
        return (f"-- The {L} 128-bit lanes of a {n}-byte vector, lane 0 first.\n"
                f"def[prelude] x86_64::{name} : (a : {vty(n)}) -> Array ({T}) {L}usize :=\n"
                f"  fun (a : {vty(n)}) =>\n    pair(Array ({T}) {L}usize,\n      {lst},\n      refl(Int, {L}int))\n")
    if name == "concat4_u8x16":
        T = aty("U8", 16)
        return (f"-- `l0 ++ l1 ++ l2 ++ l3` (64 bytes, `l0` in the low bytes).\n"
                f"def[prelude] x86_64::concat4_u8x16 : (l0 : {T}) -> (l1 : {T}) -> (l2 : {T}) -> (l3 : {T}) -> {vty(64)} :=\n"
                f"  fun (l0 : {T}) (l1 : {T}) (l2 : {T}) (l3 : {T}) =>\n"
                f"    pair({vty(64)}, seq::append U8 fst(l0) (seq::append U8 fst(l1) (seq::append U8 fst(l2) fst(l3))), refl(Int, 64int))\n")
    if name == "select4":
        T = aty("U8", 16)
        e = "#cast_u32_usize(#and_u32(control, 3u32))"
        return (f"-- SDM Select4(SRC, control): the 128-bit lane control[1:0] of a 512-bit source (as its 4 lanes).\n"
                f"def[prelude] x86_64::select4 : (src : Array ({T}) 4usize) -> (control : U32) -> {T} :=\n"
                f"  fun (src : Array ({T}) 4usize) (control : U32) =>\n"
                f"    array::index ({T}) 4usize src ({e})\n"
                f"      .linarith([]; Eq(Bool, #lt_usize({e}, 4usize), true); [1, 0, 0, 0, 0, 0, 0, 0, 0, 1])\n")
    mt = re.fullmatch(r"kbit(8|16)", name)
    if mt:
        w = mt.group(1)
        return (f"-- SDM k1[j]: bit j of an __mmask{w}.\n"
                f"def[prelude] x86_64::kbit{w} : (k : U{w}) -> (j : U32) -> Bool :=\n"
                f"  fun (k : U{w}) (j : U32) => #eq_u{w}(#and_u{w}(#wshr_u{w}(k, j), 1u{w}), 1u{w})\n")
    mt = re.fullmatch(r"mask(8|16)_of", name)
    if mt:
        w = int(mt.group(1))
        params = " ".join(f"(c{j} : Bool)" for j in range(w))
        tele = " ".join(f"(c{j} : Bool) ->" for j in range(w))
        acc = f"#wshl_u{w}(bool::as_u{w} c{w - 1}, {w - 1}u32)"
        for j in reversed(range(w - 1)):
            t = f"bool::as_u{w} c{j}" if j == 0 else f"#wshl_u{w}(bool::as_u{w} c{j}, {j}u32)"
            acc = f"#or_u{w}({t}, {acc})"
        return (f"-- The __mmask{w} whose bit j is c_j (DEST[j] := 1 iff CMP).\n"
                f"def[prelude] x86_64::mask{w}_of : {tele} U{w} :=\n  fun {params} =>\n    {acc}\n")
    mt = re.fullmatch(r"ternlog_(u32|u64)", name)
    if mt:
        l = mt.group(1)
        T = LANE[l][0]
        z = f"0{l}"
        terms = []
        for mm in range(8):
            a = "x" if mm & 4 else f"#not_{l}(x)"
            b = "y" if mm & 2 else f"#not_{l}(y)"
            c = "z" if mm & 1 else f"#not_{l}(z)"
            terms.append(f"(if #eq_u32(#and_u32(#wshr_u32(imm, {mm}u32), 1u32), 1u32) return {T} "
                         f"then #and_{l}(#and_{l}({a}, {b}), {c}) else {z})")
        acc = terms[7]
        for t in reversed(terms[:7]):
            acc = f"#or_{l}({t},\n      {acc})"
        return (f"-- VPTERNLOG on one element, as the sum of the minterms selected by imm: bit k of the result is\n"
                f"-- imm[(x_k << 2) + (y_k << 1) + z_k] (the SDM's table lookup), i.e. the OR over m = 0..7 with\n"
                f"-- imm[m] = 1 of (m[2] ? x : NOT x) AND (m[1] ? y : NOT y) AND (m[0] ? z : NOT z).\n"
                f"def[prelude] x86_64::{name} : (imm : U32) -> (x : {T}) -> (y : {T}) -> (z : {T}) -> {T} :=\n"
                f"  fun (imm : U32) (x : {T}) (y : {T}) (z : {T}) =>\n    {acc}\n")
    if name in ("madd52lo", "madd52hi"):
        lo = name == "madd52lo"
        part = "#imod(t, 4503599627370496int)" if lo else "#imod(#idiv(t, 4503599627370496int), 4503599627370496int)"
        bits = "51:0" if lo else "103:52"
        return (f"-- VPMADD52{'L' if lo else 'H'}UQ on one qword: Temp128 := ZeroExtend64(b[51:0]) * ZeroExtend64(c[51:0])\n"
                f"-- (exact, over Int); DEST := acc + ZeroExtend64(Temp128[{bits}]) mod 2^64.\n"
                f"def[prelude] x86_64::{name} : (acc : U64) -> (b : U64) -> (c : U64) -> U64 :=\n"
                f"  fun (acc : U64) (b : U64) (c : U64) =>\n"
                f"    let t : Int = #imul(#cast_u64_int(#and_u64(b, 4503599627370495u64)), #cast_u64_int(#and_u64(c, 4503599627370495u64)));\n"
                f"    #wadd_u64(acc, #int_to_sat_u64({part}))\n")
    if name == "gf2p8mul_byte":
        lets = ["    let s : U16 = #cast_u8_u16(src1byte);", "    let t0 : U16 = 0u16;"]
        for i in range(8):
            lets.append(f"    let t{i + 1} : U16 = if #ne_u8(#and_u8(src2byte, {1 << i}u8), 0u8) return U16 "
                        f"then #xor_u16(t{i}, #wshl_u16(s, {i}u32)) else t{i};")
        prev = "t8"
        for i in range(14, 7, -1):
            p = 0x11B << (i - 8)
            lets.append(f"    let r{i} : U16 = if #ne_u16(#and_u16({prev}, {1 << i}u16), 0u16) return U16 "
                        f"then #xor_u16({prev}, {p}u16) else {prev};")
            prev = f"r{i}"
        return ("-- SDM gf2p8mul_byte: carry-less product (t_{i+1} = t_i XOR (src1byte << i) if src2byte.bit[i]),\n"
                "-- then reduction by 0x11B << (i-8) for i = 14 downto 8; the low byte.\n"
                "def[prelude] x86_64::gf2p8mul_byte : (src1byte : U8) -> (src2byte : U8) -> U8 :=\n"
                "  fun (src1byte : U8) (src2byte : U8) =>\n" + "\n".join(lets) + f"\n    #cast_u16_u8({prev})\n")
    if name == "gf2_parity":
        lets = ["    let t0 : U8 = 0u8;"]
        for i in range(8):
            lets.append(f"    let t{i + 1} : U8 = #xor_u8(t{i}, #and_u8(#wshr_u8(x, {i}u32), 1u8));")
        return ("-- SDM parity(x): t := 0; FOR i := 0 to 7: t = t xor x.bit[i] (an xor of bit extractions).\n"
                "def[prelude] x86_64::gf2_parity : (x : U8) -> U8 :=\n  fun (x : U8) =>\n" + "\n".join(lets) + "\n    t8\n")
    if name == "gf2p8_affine_byte":
        par = need("gf2_parity")
        lets = []
        for i in range(8):
            lets.append(f"    let r{i} : U8 = #xor_u8({par} (#and_u8(#cast_u64_u8(#wshr_u64(tsrc2qw, {8 * (7 - i)}u32)), src1byte)), "
                        f"#and_u8(#cast_u32_u8(#wshr_u32(imm, {i}u32)), 1u8));")
        acc = "#wshl_u8(r7, 7u32)"
        for i in reversed(range(7)):
            t = "r0" if i == 0 else f"#wshl_u8(r{i}, {i}u32)"
            acc = f"#or_u8({t}, {acc})"
        return ("-- SDM affine_byte: retbyte.bit[i] := parity(tsrc2qw.byte[7-i] AND src1byte) XOR imm8.bit[i].\n"
                "def[prelude] x86_64::gf2p8_affine_byte : (tsrc2qw : U64) -> (src1byte : U8) -> (imm : U32) -> U8 :=\n"
                "  fun (tsrc2qw : U64) (src1byte : U8) (imm : U32) =>\n" + "\n".join(lets) + f"\n    {acc}\n")
    if name == "gf2p8_inverse":
        mul = need("gf2p8mul_byte")
        lets = ["    let s0 : U8 = x;", "    let a0 : U8 = 1u8;"]
        for i in range(7):
            lets.append(f"    let s{i + 1} : U8 = {mul} s{i} s{i};")
            lets.append(f"    let a{i + 1} : U8 = {mul} a{i} s{i + 1};")
        return ("-- SDM inverse(x) (the table of GF2P8AFFINEINVQB): x^254 = x^2 x^4 .. x^128 in GF(2^8) mod 0x11B\n"
                "-- (inverse(0) = 0); the square-and-multiply chain of the executable model.\n"
                "def[prelude] x86_64::gf2p8_inverse : (x : U8) -> U8 :=\n  fun (x : U8) =>\n" + "\n".join(lets) + "\n    a7\n")
    if name == "multishift_byte":
        lets = ["    let ctrl : U32 = #cast_u8_u32(#and_u8(c, 63u8));"]
        for k in range(8):
            lets.append(f"    let b{k} : U8 = #cast_u64_u8(#and_u64(#wshr_u64(tcur, #and_u32(#wadd_u32(ctrl, {k}u32), 63u32)), 1u64));")
        acc = "#wshl_u8(b7, 7u32)"
        for k in reversed(range(7)):
            t = "b0" if k == 0 else f"#wshl_u8(b{k}, {k}u32)"
            acc = f"#or_u8({t}, {acc})"
        return ("-- One VPMULTISHIFTQB byte: ctrl := c & 63; res.bit[k] := tcur.bit[(ctrl+k) mod 64] for k < 8.\n"
                "def[prelude] x86_64::multishift_byte : (tcur : U64) -> (c : U8) -> U8 :=\n"
                "  fun (tcur : U64) (c : U8) =>\n" + "\n".join(lets) + f"\n    {acc}\n")
    mt = re.fullmatch(r"(shld|shrd)_(u32|u64)", name)
    if mt:
        kind, l = mt.group(1), mt.group(2)
        T = LANE[l][0]
        w = 32 if l == "u32" else 64
        if kind == "shld":
            doc = (f"-- VBMI2 SHLD on one element: concat(hi, lo) << s, the upper half (s < {w}): hi for s = 0, else\n"
                   f"-- (hi << s) OR (lo >> ({w} - s)).")
            body = f"if #eq_u32(s, 0u32) return {T} then hi else #or_{l}(#wshl_{l}(hi, s), #wshr_{l}(lo, #wsub_u32({w}u32, s)))"
            params = f"(hi : {T}) (lo : {T}) (s : U32)"
            tele = f"(hi : {T}) -> (lo : {T}) -> (s : U32) -> {T}"
        else:
            doc = (f"-- VBMI2 SHRD on one element: concat(hi, lo) >> s, the lower half (s < {w}): lo for s = 0, else\n"
                   f"-- (lo >> s) OR (hi << ({w} - s)).")
            body = f"if #eq_u32(s, 0u32) return {T} then lo else #or_{l}(#wshr_{l}(lo, s), #wshl_{l}(hi, #wsub_u32({w}u32, s)))"
            params = f"(lo : {T}) (hi : {T}) (s : U32)"
            tele = f"(lo : {T}) -> (hi : {T}) -> (s : U32) -> {T}"
        return f"{doc}\ndef[prelude] x86_64::{name} : {tele} :=\n  fun {params} =>\n    {body}\n"
    raise KeyError(name)


# ---------------------------------------------------------------------------
# Model bodies.

def core_ty(t):
    if t.startswith("V"):
        return vty(int(t[1:]))
    return t


def lanes_of(width, lane):
    return width // LANE[lane][1]


def view(width, lane, arg):
    k = lanes_of(width, lane)
    if lane == "u8":
        return arg
    if width == 16:  # the 128-bit views of core/x86_64.core
        return f"x86_64::view_{lane} {arg}"
    return f"{need(f'view_{lane}x{k}')} {arg}"


def from_(width, lane, arg):
    k = lanes_of(width, lane)
    if lane == "u8":
        return arg
    return f"{need(f'from_{lane}x{k}')} ({arg})"


def body(md):
    import re
    for dep in re.findall(r"x86_64::(\w+)", md.get("op", "")):
        need(dep)  # element helpers named in the per-element pseudocode
    kind, w = md["kind"], md["width"]
    p = [x for x, _ in md["params"]]
    lane = md.get("lane")
    if kind == "copy":
        return f"{need(f'map_u8x{w}')} (fun (x : U8) => x) {p[0]}"
    if kind in ("map1", "map2", "map3"):
        ar = int(kind[3])
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        names = ["x", "y", "z"][:ar]
        lam = "fun " + " ".join(f"({n} : {T})" for n in names) + f" => {md['op']}"
        mname = need(f"map{'' if ar == 1 else ar}_{lane}x{k}")
        args = " ".join(f"({view(w, lane, a)})" if lane != "u8" else a for a in p)
        inner = f"{mname} ({lam}) {args}"
        return from_(w, lane, inner) if lane != "u8" else inner
    if kind == "ternlog":
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        t = need(f"ternlog_{lane}")
        mname = need(f"map3_{lane}x{k}")
        args = " ".join(f"({view(w, lane, a)})" for a in p)
        return from_(w, lane, f"{mname} (fun (x : {T}) (y : {T}) (z : {T}) => {t} IMM8 x y z) {args}")
    if kind == "pshufb":
        L = w // 16
        lanes = need(f"lanes128_u8x{w}")
        T = aty("U8", 16)
        lets = [f"let t : Array ({T}) {L}usize = {lanes} {p[0]};"]
        for l in range(L):
            lets.append(f"let t{l} : {T} = array::index ({T}) {L}usize t {l}usize .refl(Bool, true);")
        pb = need("pshufb_byte")
        terms = [f"({pb} t{j // 16} ({ix('U8', w, p[1], j)}))" for j in range(w)]
        return "\n    ".join(lets) + f"\n    {need(f'u8x{w}')}\n" + wrap(terms, 1, "      ")
    if kind == "permvar":
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        tab, idx = md["table"], md["index"]
        msk = k - 1
        e = f"#cast_{lane}_usize(#and_{lane}(i, {msk}{lane}))"
        get = (f"array::index {T} {k}usize src ({e})\n        .linarith([]; Eq(Bool, #lt_usize({e}, {k}usize), true); "
               f"[1, 0, 0, 0, 0, 0, 0, 0, 0, 1])")
        mname = need(f"map_{lane}x{k}")
        src = view(w, lane, tab) if lane != "u8" else tab
        inner = f"{mname} (fun (i : {T}) =>\n        {get})\n      ({view(w, lane, idx) if lane != 'u8' else idx})"
        return f"let src : {aty(T, k)} = {src};\n    " + (from_(w, lane, inner) if lane != "u8" else inner)
    if kind == "perm2var":
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        msk = k - 1
        e = f"#cast_{lane}_usize(#and_{lane}(i, {msk}{lane}))"
        cert = f".linarith([]; Eq(Bool, #lt_usize({e}, {k}usize), true); [1, 0, 0, 0, 0, 0, 0, 0, 0, 1])"
        mname = need(f"map_{lane}x{k}")
        a, idx, b = p
        ta = view(w, lane, a) if lane != "u8" else a
        tb = view(w, lane, b) if lane != "u8" else b
        sel = (f"if #ne_{lane}(#and_{lane}(i, {k}{lane}), 0{lane}) return {T}\n"
               f"        then array::index {T} {k}usize tb ({e})\n          {cert}\n"
               f"        else array::index {T} {k}usize ta ({e})\n          {cert}")
        inner = f"{mname} (fun (i : {T}) =>\n        {sel})\n      ({view(w, lane, idx) if lane != 'u8' else idx})"
        return (f"let ta : {aty(T, k)} = {ta};\n    let tb : {aty(T, k)} = {tb};\n    "
                + (from_(w, lane, inner) if lane != "u8" else inner))
    if kind == "shuf128":
        lanes = need("lanes128_u8x64")
        sel = need("select4")
        T = aty("U8", 16)
        return (f"let la : Array ({T}) 4usize = {lanes} a;\n    let lb : Array ({T}) 4usize = {lanes} b;\n"
                f"    {need('concat4_u8x16')} ({sel} la MASK) ({sel} la (#wshr_u32(MASK, 2u32)))\n"
                f"      ({sel} lb (#wshr_u32(MASK, 4u32))) ({sel} lb (#wshr_u32(MASK, 6u32)))")
    if kind == "unpack":
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        per = 16 // LANE[lane][1]  # elements per 128-bit lane
        terms = []
        for L in range(w // 16):
            base = per * L
            src = range(base + per // 2, base + per) if md["hi"] else range(base, base + per // 2)
            for e in src:
                terms.append(f"({ix(T, k, 'x', e)})")
                terms.append(f"({ix(T, k, 'y', e)})")
        return (f"let x : {aty(T, k)} = {view(w, lane, 'a')};\n    let y : {aty(T, k)} = {view(w, lane, 'b')};\n    "
                + from_(w, lane, f"{need(f'{lane}x{k}')}\n" + wrap(terms, 2, "        ")))
    if kind == "splat":
        k = lanes_of(w, lane)
        return from_(w, lane, f"{need(f'{lane}x{k}')} " + " ".join(["a"] * k))
    if kind in ("blendm", "maskz", "maskm"):
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        kb = need(f"kbit{k}")
        if kind == "blendm":
            mname = need(f"imap2_{lane}x{k}")
            lam = f"fun (j : U32) (x : {T}) (y : {T}) => if {kb} k j return {T} then y else x"
            args = f"({view(w, lane, 'a')}) ({view(w, lane, 'b')})"
        elif kind == "maskz":
            mname = need(f"imap_{lane}x{k}")
            lam = f"fun (j : U32) (x : {T}) => if {kb} k j return {T} then x else 0{lane}"
            args = f"({view(w, lane, 'a')})"
        else:
            mname = need(f"imap2_{lane}x{k}")
            lam = f"fun (j : U32) (s : {T}) (x : {T}) => if {kb} k j return {T} then x else s"
            args = f"({view(w, lane, 'src')}) ({view(w, lane, 'a')})"
        return from_(w, lane, f"{mname} ({lam}) {args}")
    if kind == "cmp":
        T = LANE[lane][0]
        k = lanes_of(w, lane)
        mk = need(f"mask{k}_of")
        op = {"lt": "lt", "eq": "eq"}[md["cmp"]]
        terms = [f"(#{op}_{lane}({ix(T, k, 'x', j)}, {ix(T, k, 'y', j)}))" for j in range(k)]
        return (f"let x : {aty(T, k)} = {view(w, lane, 'a')};\n    let y : {aty(T, k)} = {view(w, lane, 'b')};\n"
                f"    {mk}\n" + wrap(terms, 1, "      "))
    if kind == "affine":
        k = w // 8
        mview = "x86_64::view_u64 a" if w == 16 else f"{need(f'view_u64x{k}')} a"
        f = need("gf2p8_affine_byte")
        inv = need("gf2p8_inverse") if md["inv"] else None
        terms = []
        for j in range(k):
            for b in range(8):
                xb = ix("U8", w, "x", 8 * j + b)
                xb = f"({inv} ({xb}))" if inv else f"({xb})"
                terms.append(f"({f} ({ix('U64', k, 'mat', j)}) {xb} B)")
        return f"let mat : {aty('U64', k)} = {mview};\n    {need(f'u8x{w}')}\n" + wrap(terms, 1, "      ")
    if kind == "multishift":
        f = need("multishift_byte")
        terms = [f"({f} ({ix('U64', 8, 't', i)}) ({ix('U8', 64, 'a', 8 * i + j)}))" for i in range(8) for j in range(8)]
        return f"let t : {aty('U64', 8)} = {need('view_u64x8')} b;\n    {need('u8x64')}\n" + wrap(terms, 1, "      ")
    if kind == "blendimm":
        k = lanes_of(w, lane)
        mname = need(f"imap2_u32x{k}")
        lam = "fun (j : U32) (x : U32) (y : U32) => if #eq_u32(#and_u32(#wshr_u32(IMM8, j), 1u32), 1u32) return U32 then y else x"
        return from_(w, lane, f"{mname} ({lam}) ({view(w, lane, 'a')}) ({view(w, lane, 'b')})")
    if kind == "alignr":
        lanes = need("lanes128_u8x32")
        T = aty("U8", 16)
        cc = need("concat_u8x16")
        pa = need("palignr_byte")
        lets = [f"let la : Array ({T}) 2usize = {lanes} a;", f"let lb : Array ({T}) 2usize = {lanes} b;"]
        for l in range(2):
            lets.append(f"let c{l} : {vty(32)} = {cc} (array::index ({T}) 2usize lb {l}usize .refl(Bool, true)) "
                        f"(array::index ({T}) 2usize la {l}usize .refl(Bool, true));")
        terms = []
        for l in range(2):
            for i in range(16):
                terms.append(f"({pa} c{l} IMM8)" if i == 0 else f"({pa} c{l} (#wadd_u32(IMM8, {i}u32)))")
        return "\n    ".join(lets) + f"\n    {need('u8x32')}\n" + wrap(terms, 1, "      ")
    raise KeyError(kind)


def model_text(md):
    name = md["name"]
    tele = []
    lam = []
    if md["imm"]:
        n = md["imm"]
        tele.append(f"({n} : U32) -> (.h{n} : Eq(Bool, #le_u32({n}, 255u32), true))")
        lam.append(f"({n} : U32) (.h{n} : Eq(Bool, #le_u32({n}, 255u32), true))")
    for (x, t) in md["params"]:
        tele.append(f"({x} : {core_ty(t)})")
        lam.append(f"({x} : {core_ty(t)})")
    ty = " -> ".join(tele) + f" -> {core_ty(md['ret'])}"
    b = body(md)
    return (f"-- {name} — {md['instr']} ({', '.join(md['feats'])}); src/x86_64/{md['src'].lower()}.rs.\n"
            f"def[intrinsic] x86_64::{name} :\n    {ty} :=\n  fun {' '.join(lam)} =>\n    {b}\n")


HEADER = """\
-- sandblaster target semantics: x86_64 256/512-bit families (MODELS.md §10):
-- AVX-512F/BW/VL/DQ, AVX512IFMA, GFNI, AVX512VBMI/VBMI2, AVX512VPOPCNTDQ,
-- AVX512BITALG and AVX/AVX2.
--
-- GENERATED by gen/x86_64_avx.py from its model table; do not edit by
-- hand (regenerate and review the diff). TRUSTED: this file is part of TCB
-- item 4 (DESIGN.md §1.1), like core/x86_64.core, which it extends: the two
-- files are loaded as ONE core text (`coretext::core_text(Arch::X86_64)` is
-- their concatenation), so the helpers of core/x86_64.core (u8x16, view_u64,
-- pshufb_byte, palignr_byte, concat_u8x16, ...) are reused here.
--
-- Conventions (MODELS.md "Core text", §10):
--   * `__m256i` = `Array U8 32usize`, `__m512i` = `Array U8 64usize`, byte i =
--     bits 8i+7:8i; typed views view_u16/u32/u64xK read lanes little-endian
--     through the prelude's from_le_bytes, and from_*xK are their inverses
--     (byte b of lane x = cast_u8(x >> 8b)), exactly the pattern of the §5.7
--     byte rules, so view (from l) collapses to l on symbolic data.
--   * `__mmask8` / `__mmask16` are U8 / U16; bit j belongs to element j.
--   * Immediates come first as relevant U32 parameters with the irrelevant
--     range proof `(.hIMM8 : Eq(Bool, #le_u32(IMM8, 255u32), true))` (named
--     after the stdarch const: IMM8, MASK, B).
--   * Signed stdarch scalars (_mm512_set1_epi32, ...) are their two's-complement
--     bits (U32 / U64).
--   * Lanewise instructions are `from (mapN f (view a) ..)` with `f` the
--     per-element pseudocode; cross-lane ones index their sources with literal
--     lanes or with a linarith-certified computed lane.
"""


def core_text():
    models = [model_text(md) for md in MODELS]  # fills HELPERS
    out = [HEADER]
    out.append("\n-- ---------------------------------------------------------------------------\n"
               "-- Helpers (def[prelude]): constructors, views, maps, element functions.\n"
               "-- ---------------------------------------------------------------------------\n")
    for name, text in HELPERS.items():
        out.append("\n" + text)
    out.append("\n-- ---------------------------------------------------------------------------\n"
               "-- Intrinsic models (def[intrinsic]), in registry order.\n"
               "-- ---------------------------------------------------------------------------\n")
    for t in models:
        out.append("\n" + t)
    out.append(WIDE_HELPERS)
    return "".join(out)


# The `sandblaster::arch::x86_64` load/store helpers of the 256/512-bit lane
# kernels (plan O10, the lane functor's pack and unpack): like
# `x86_64::load_u32x4` in core/x86_64.core, `def[intrinsic]` wrappers of the
# unaligned load/store models over the little-endian memory image of a
# `[u32; N]`, opaque on symbolic data.
WIDE_HELPERS = """
-- ---------------------------------------------------------------------------
-- Load/store helpers of the lane kernels (plan O10): `[u32; 8]` / `[u32; 16]`
-- as the 32 / 64 bytes of their little-endian memory image.
-- ---------------------------------------------------------------------------

-- load_u32x8(a: &[u32; 8]) = _mm256_loadu_si256(a.as_ptr().cast()).
def[intrinsic] x86_64::load_u32x8 : (a : Array U32 8usize) -> Array U8 32usize :=
  fun (a : Array U32 8usize) => x86_64::_mm256_loadu_si256 (x86_64::from_u32x8 a)

-- store_u32x8(v) = the [u32; 8] whose memory image _mm256_storeu_si256 writes.
def[intrinsic] x86_64::store_u32x8 : (v : Array U8 32usize) -> Array U32 8usize :=
  fun (v : Array U8 32usize) => x86_64::view_u32x8 (x86_64::_mm256_storeu_si256 v)

-- load_u32x16(a: &[u32; 16]) = _mm512_loadu_si512(a.as_ptr().cast()).
def[intrinsic] x86_64::load_u32x16 : (a : Array U32 16usize) -> Array U8 64usize :=
  fun (a : Array U32 16usize) => x86_64::_mm512_loadu_si512 (x86_64::from_u32x16 a)

-- store_u32x16(v) = the [u32; 16] whose memory image _mm512_storeu_si512 writes.
def[intrinsic] x86_64::store_u32x16 : (v : Array U8 64usize) -> Array U32 16usize :=
  fun (v : Array U8 64usize) => x86_64::view_u32x16 (x86_64::_mm512_storeu_si512 v)
"""


def rust_coretext():
    CT = {"V64": "U8X64", "V32": "U8X32", "V16": "U8X16", "U8": "Word(Lane::U8)", "U16": "Word(Lane::U16)",
          "U32": "Word(Lane::U32)", "U64": "Word(Lane::U64)"}
    lines = []
    for md in MODELS:
        imms = f'imm("{md["imm"]}", 0, 255)' if md["imm"] else ""
        ps = ", ".join(f"{x}: {CT[t]}" for x, t in md["params"])
        lines.append(f"    x86!({md['name']}, [{imms}], [{ps}], {CT[md['ret']]}),")
    return "\n".join(lines)


def rust_registry():
    out = []
    for md in MODELS:
        fs = ", ".join(f'"{f}"' for f in md["feats"])
        its = ", ".join(md["items"])
        imm_s = "Some(0..=255)" if md["imm"] else "None"
        out.append(f'    wide!({md["src"]}, {md["name"]}, [{fs}], "{md["instr"]}", {imm_s}, [{its}]),')
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Rust emitters: the hardware wrappers (untrusted harness) and campaign rows.

RTY = {"V64": "[u8; 64]", "V32": "[u8; 32]", "V16": "[u8; 16]", "U8": "u8", "U16": "u16", "U32": "i32", "U64": "i64"}
TO = {"V64": "m512", "V32": "m256", "V16": "m128"}
FROM = {"V64": "b512", "V32": "b256", "V16": "b128"}


def hw_module():
    out = [HW_HEADER]
    arms = []
    for md in MODELS:
        n = md["name"]
        feats = ",".join(md["feats"])
        ps = md["params"]
        ret = md["ret"]
        rty = RTY[ret]
        conv = lambda x, t: f"{TO[t]}({x})" if t in TO else x
        back = lambda e: f"{FROM[ret]}({e})" if ret in FROM else e
        if md["kind"] == "copy" and "loadu" in n:
            w = md["width"]
            out.append(f"/// `{n}` reading the {w} bytes of `mem`.\n#[target_feature(enable = \"{feats}\")]\n"
                       f"pub fn {n}(mem: &[u8; {w}]) -> [u8; {w}] {{\n"
                       f"    // SAFETY: `mem` is valid for reading {w} bytes; the load has no alignment requirement.\n"
                       f"    {FROM[ret]}(unsafe {{ arch::{n}(mem.as_ptr().cast()) }})\n}}\n")
            arms.append(f'        "{n}" => diff::diff1(name, n, s, |a: [u8; {w}]| model::{n}(&a), |a: [u8; {w}]| unsafe {{ {n}(&a) }}),')
            continue
        if md["kind"] == "copy":
            w = md["width"]
            out.append(f"/// `{n}` into an unaligned slot of a sentinel-filled buffer; returns the {w} bytes written and\n"
                       f"/// panics if any byte outside them changed.\n#[target_feature(enable = \"{feats}\")]\n"
                       f"pub fn {n}(a: [u8; {w}]) -> [u8; {w}] {{\n    let mut buf = [SENTINEL; {w + 34}];\n"
                       f"    // SAFETY: `buf[17..{17 + w}]` is in bounds and writable; the store has no alignment requirement.\n"
                       f"    unsafe {{ arch::{n}(buf.as_mut_ptr().add(17).cast(), {TO[ps[0][1]]}(a)) }};\n"
                       f"    assert!(buf[..17].iter().chain(&buf[{17 + w}..]).all(|&x| x == SENTINEL), \"{n} wrote outside its {w} bytes\");\n"
                       f"    buf[17..{17 + w}].try_into().expect(\"{w} bytes\")\n}}\n")
            arms.append(f'        "{n}" => diff::diff1(name, n, s, model::{n}, |a| unsafe {{ {n}(a) }}),')
            continue
        args = ", ".join(f"{x}: {RTY[t]}" for x, t in ps)
        call_args = ", ".join(conv(x, t) for x, t in ps)
        names = ", ".join(x for x, _ in ps)
        k = len(ps)
        if md["imm"]:
            ct = md["consty"]
            fty = f"unsafe fn({', '.join(RTY[t] for _, t in ps)}) -> {rty}"
            out.append(f"#[target_feature(enable = \"{feats}\")]\nfn {n}_imm<const IMM: {ct}>({args}) -> {rty} {{\n"
                       f"    {back(f'arch::{n}::<IMM>({call_args})')}\n}}\n"
                       f"fn {n}_table() -> &'static [{fty}; 256] {{\n"
                       f"    static T: std::sync::OnceLock<[{fty}; 256]> = std::sync::OnceLock::new();\n"
                       f"    T.get_or_init(|| imm8_table!({n}_imm, {fty}))\n}}\n"
                       f"/// `{n}::<{md['imm']}>` with the immediate as an argument.\n#[target_feature(enable = \"{feats}\")]\n"
                       f"pub fn {n}({args}, imm: i32) -> {rty} {{\n"
                       f"    // SAFETY: the table entries require `{feats}`, which this function has.\n"
                       f"    unsafe {{ {n}_table()[imm8(imm, \"{n}\")]({names}) }}\n}}\n")
            arms.append(f'        "{n}" => diff::diff_imm{k}(name, imms(), n, s, model::{n}, |{names}, i| unsafe {{ {n}({names}, i) }}),')
        else:
            out.append(f"/// `{n}`.\n#[target_feature(enable = \"{feats}\")]\npub fn {n}({args}) -> {rty} {{\n"
                       f"    {back(f'arch::{n}({call_args})')}\n}}\n")
            arms.append(f'        "{n}" => diff::diff{k}(name, n, s, model::{n}, |{names}| unsafe {{ {n}({names}) }}),')
    out.append(HW_FOOTER.replace("@ARMS@", "\n".join(arms)))
    return "\n".join(out)


HW_HEADER = """//! GENERATED by `gen/x86_64_avx.py` (`python3 gen/x86_64_avx.py hw > src/hw/x86_64_wide.rs`); do not edit
//! by hand. The real 256/512-bit x86 intrinsics (AVX-512F/BW/VL/DQ, IFMA, GFNI, VBMI/VBMI2,
//! VPOPCNTDQ/BITALG, AVX/AVX2) on the model representation, and their differential campaigns
//! (DESIGN.md §9.2 "Validation"; MODELS.md §10).
//!
//! Every wrapper has the signature of the model of the same name in [`crate::x86_64`] (`__m512i`
//! as `[u8; 64]`, `__m256i` as `[u8; 32]`, `__m128i` as `[u8; 16]`, `__mmaskN` as `uN`, signed
//! scalars as `i32`/`i64`, immediates as `i32` dispatched through tables of 256
//! monomorphizations). Untrusted harness code: a wrong wrapper can only make a campaign fail.
//!
//! # Safety
//!
//! The wrappers are safe `#[target_feature]` functions: calling one from code without the
//! feature enabled is `unsafe`, and the caller must ensure the running CPU has the features
//! ([`super::x86_64::run_model`] checks every feature of the model with run-time detection
//! before [`campaign`] runs). The vector conversions are `transmute`s between types of the same
//! size whose every bit pattern is valid, byte `i` = bits `8i+7:8i` (little-endian), the §9.2
//! representation.
//!
//! The AVX-512 intrinsics are stable since Rust 1.89 (the workspace declares
//! `rust-version = 1.88`); this module, compiled only for x86_64, needs 1.89+
//! (the campaigns use 1.98.1).
#![allow(clippy::missing_safety_doc, clippy::incompatible_msrv, clippy::type_complexity)]

use crate::diff::{self, Outcome};
use crate::x86_64 as model;
use core::arch::x86_64 as arch;
use core::arch::x86_64::{__m128i, __m256i, __m512i};
use core::mem::transmute;
use std::ops::RangeInclusive;

use super::imm8_table;

#[inline(always)]
fn m512(a: [u8; 64]) -> __m512i {
    // SAFETY: same size, every bit pattern valid for both.
    unsafe { transmute(a) }
}
#[inline(always)]
fn b512(v: __m512i) -> [u8; 64] {
    // SAFETY: as `m512`.
    unsafe { transmute(v) }
}
#[inline(always)]
fn m256(a: [u8; 32]) -> __m256i {
    // SAFETY: as `m512`.
    unsafe { transmute(a) }
}
#[inline(always)]
fn b256(v: __m256i) -> [u8; 32] {
    // SAFETY: as `m512`.
    unsafe { transmute(v) }
}
#[inline(always)]
fn m128(a: [u8; 16]) -> __m128i {
    // SAFETY: as `m512`.
    unsafe { transmute(a) }
}
#[inline(always)]
fn b128(v: __m128i) -> [u8; 16] {
    // SAFETY: as `m512`.
    unsafe { transmute(v) }
}

/// Byte written around stores to detect writes outside the stored bytes.
const SENTINEL: u8 = 0xa5;

fn imm8(imm: i32, what: &str) -> usize {
    usize::try_from(imm).ok().filter(|&i| i < 256).unwrap_or_else(|| panic!("{what}: immediate {imm} out of range"))
}
"""

HW_FOOTER = """
/// The names of the models with a wrapper here, in registry order.
pub const NAMES: &[&str] = &[@NAMES@];

/// The differential campaign of 256/512-bit model `name` (`n` random cases, seed `s`, every
/// immediate of `imms`), or `None` if `name` is not one. The caller has detected every
/// feature of the model on the running CPU.
pub(super) fn campaign(name: &str, n: u64, s: u64, imms: Option<RangeInclusive<i32>>) -> Option<Outcome> {
    let imms = || imms.clone().expect("immediate model");
    // SAFETY (every `unsafe` block below): it calls a `#[target_feature]` wrapper whose
    // features the caller detected on this CPU.
    Some(match name {
@ARMS@
        _ => return None,
    })
}
"""


def consistency_arms():
    arms = []
    for md in MODELS:
        n = md["name"]
        k = len(md["params"])
        if md["kind"] == "copy" and "loadu" in n:
            w = md["width"]
            arms.append(f'        "{n}" => diff1(name, n, s, |a: [u8; {w}]| x86::{n}(&a), |a: [u8; {w}]| r::{n}(&a)),')
        elif md["imm"]:
            arms.append(f'        "{n}" => diff_imm{k}(name, 0..=255, n, s, x86::{n}, r::{n}),')
        else:
            arms.append(f'        "{n}" => diff{k}(name, n, s, x86::{n}, r::{n}),')
    return "\n".join(arms)


KTY = {"V64": "Kv<64>", "V32": "Kv<32>", "V16": "Kv<16>", "U8": "u8", "U16": "u16", "U32": "i32", "U64": "i64"}


def kernel_arms():
    """Rows of kernel::crosscheck_part: the wide vectors as `Kv<N>` (curated kernel corners)."""
    arms = []
    for md in MODELS:
        n = md["name"]
        ps = md["params"]
        k = len(ps)
        args = ", ".join(f"{x}: {KTY[t]}" for x, t in ps)
        unwrap = lambda x, t: f"{x}.0" if t.startswith("V") else x
        call_args = ", ".join(unwrap(x, t) for x, t in ps)
        if md["kind"] == "copy" and "loadu" in n:
            call_args = f"&{ps[0][0]}.0"
        ret_wrap = (lambda e: f"Kv({e})") if md["ret"].startswith("V") else (lambda e: e)
        if md["imm"]:
            body = ret_wrap(f"x86::{n}({call_args}, imm)")
            arms.append(f'        (Arch::X86_64, "{n}") => ci{k}(ck, m, cfg, p(), |{args}, imm: i32| {body}),')
        else:
            body = ret_wrap(f"x86::{n}({call_args})")
            arms.append(f'        (Arch::X86_64, "{n}") => c{k}(ck, m, cfg, |{args}| {body}),')
    return "\n".join(arms)


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "core"
    if what == "core":
        sys.stdout.write(core_text())
    elif what == "coretext":
        print(rust_coretext())
    elif what == "registry":
        print(rust_registry())
    elif what == "hw":
        sys.stdout.write(hw_module().replace("@NAMES@", ", ".join(f'"{md["name"]}"' for md in MODELS)))
    elif what == "kernel":
        print(kernel_arms())
    elif what == "consistency":
        print(consistency_arms())
    elif what == "names":
        print(" ".join(md["name"] for md in MODELS))
    else:
        sys.exit(f"unknown mode {what}")
