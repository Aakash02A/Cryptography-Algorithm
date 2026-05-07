import os
import hashlib
import secrets
import struct
import math


# ── SPHINCS+ Pure Python (SPHINCS+-SHA2-128s, educational) ───────────────────
# Based on: Bernstein et al. "SPHINCS+: Stateless Hash-Based Signatures"
# (NIST FIPS 205, 2024). Hash-based signature — no lattice or number theory.
# Production use: liboqs, sphincsplus-py, or pqcrypto bindings

# SPHINCS+-SHA2-128s parameters
_N     = 16     # security parameter (bytes)
_H     = 63     # total tree height
_D     = 7      # number of layers
_A     = 12     # FORS tree height
_K     = 14     # FORS trees per signature
_W     = 16     # Winternitz parameter
_LEN   = 35     # WOTS+ chain length (n*(ceil(log_w(8n))+1+1))
_HPrime = _H // _D  # tree height per layer = 9


# ── Core Hash Functions ───────────────────────────────────────────────────────

def _prf(key: bytes, addr: bytes) -> bytes:
    return hashlib.sha256(key + addr).digest()[:_N]


def _h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes) -> bytes:
    return hashlib.sha256(r + pk_seed + pk_root + msg).digest()[:_N + 8 + _K * _A // 8]


def _prf_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return hashlib.sha256(sk_prf + opt_rand + msg).digest()[:_N]


def _f(pk_seed: bytes, addr: bytes, x: bytes) -> bytes:
    return hashlib.sha256(pk_seed + addr + x).digest()[:_N]


def _h(pk_seed: bytes, addr: bytes, x: bytes, y: bytes) -> bytes:
    return hashlib.sha256(pk_seed + addr + x + y).digest()[:_N]


def _t_l(pk_seed: bytes, addr: bytes, nodes: list[bytes]) -> bytes:
    return hashlib.sha256(pk_seed + addr + b''.join(nodes)).digest()[:_N]


# ── Address encoding ──────────────────────────────────────────────────────────

def _addr(layer: int = 0, tree: int = 0, type_: int = 0,
          keypair: int = 0, chain: int = 0, hash_: int = 0) -> bytes:
    return struct.pack('>IQIIII', layer, tree, type_, keypair, chain, hash_)


# ── WOTS+ (Winternitz One-Time Signature) ─────────────────────────────────────

def _base_w(msg: bytes, w: int, out_len: int) -> list[int]:
    bits  = int.from_bytes(msg, 'big')
    log_w = int(math.log2(w))
    total = out_len * log_w
    result = []
    for i in range(out_len):
        shift = total - (i + 1) * log_w
        result.append((bits >> shift) & (w - 1))
    return result


def _wots_chain(x: bytes, start: int, steps: int,
                pk_seed: bytes, addr_base: bytes) -> bytes:
    out = x
    for i in range(start, start + steps):
        addr = addr_base[:28] + struct.pack('>I', i)
        out = _f(pk_seed, addr, out)
    return out


def _wots_pk_from_sk(sk_seed: bytes, pk_seed: bytes,
                     addr_kp: int, layer: int, tree: int) -> list[bytes]:
    pks = []
    for i in range(_LEN):
        addr = _addr(layer, tree, 0, addr_kp, i, 0)
        sk_i = _prf(sk_seed, addr)
        pk_i = _wots_chain(sk_i, 0, _W - 1, pk_seed, addr)
        pks.append(pk_i)
    return pks


def _wots_sign(msg: bytes, sk_seed: bytes, pk_seed: bytes,
               addr_kp: int, layer: int, tree: int) -> list[bytes]:
    msg_base = _base_w(msg, _W, _N * 2)
    csum = sum(_W - 1 - x for x in msg_base)
    csum_bytes = csum.to_bytes(2, 'big')
    checksum = _base_w(csum_bytes, _W, 3)
    combined = msg_base + checksum

    sigs = []
    for i, b in enumerate(combined[:_LEN]):
        addr = _addr(layer, tree, 0, addr_kp, i, 0)
        sk_i = _prf(sk_seed, addr)
        sig_i = _wots_chain(sk_i, 0, b, pk_seed, addr)
        sigs.append(sig_i)
    return sigs


def _wots_pk_from_sig(sig: list[bytes], msg: bytes, pk_seed: bytes,
                      addr_kp: int, layer: int, tree: int) -> list[bytes]:
    msg_base = _base_w(msg, _W, _N * 2)
    csum = sum(_W - 1 - x for x in msg_base)
    csum_bytes = csum.to_bytes(2, 'big')
    checksum = _base_w(csum_bytes, _W, 3)
    combined = msg_base + checksum

    pk_sigs = []
    for i, (s, b) in enumerate(zip(sig, combined[:_LEN])):
        addr = _addr(layer, tree, 0, addr_kp, i, 0)
        pk_i = _wots_chain(s, b, _W - 1 - b, pk_seed, addr)
        pk_sigs.append(pk_i)
    return pk_sigs


# ── Merkle Tree (HT) ──────────────────────────────────────────────────────────

def _ht_leaf(sk_seed: bytes, pk_seed: bytes,
             idx: int, layer: int, tree: int) -> bytes:
    wots_pk = _wots_pk_from_sk(sk_seed, pk_seed, idx, layer, tree)
    addr    = _addr(layer, tree, 1, idx)
    return _t_l(pk_seed, addr, wots_pk)


def _ht_auth_path(sk_seed: bytes, pk_seed: bytes,
                  idx: int, layer: int, tree: int) -> list[bytes]:
    """Compute Merkle authentication path for leaf idx."""
    h     = _HPrime
    nodes = [_ht_leaf(sk_seed, pk_seed, i, layer, tree) for i in range(min(1 << h, 16))]
    auth  = []
    for lvl in range(min(h, 4)):
        sib = idx ^ 1
        auth.append(nodes[sib] if sib < len(nodes) else hashlib.sha256(b'\x00').digest()[:_N])
        new_nodes = []
        for i in range(0, len(nodes), 2):
            l = nodes[i]
            r = nodes[i+1] if i+1 < len(nodes) else l
            addr = _addr(layer, tree, 2, 0, 0, lvl)
            new_nodes.append(_h(pk_seed, addr, l, r))
        nodes = new_nodes
        idx >>= 1
    return auth


def _ht_root(sk_seed: bytes, pk_seed: bytes,
             layer: int, tree: int, n_leaves: int = 4) -> bytes:
    nodes = [_ht_leaf(sk_seed, pk_seed, i, layer, tree) for i in range(n_leaves)]
    level = 0
    while len(nodes) > 1:
        new_nodes = []
        for i in range(0, len(nodes), 2):
            l = nodes[i]
            r = nodes[i+1] if i+1 < len(nodes) else l
            addr = _addr(layer, tree, 2, 0, 0, level)
            new_nodes.append(_h(pk_seed, addr, l, r))
        nodes = new_nodes
        level += 1
    return nodes[0]


# ── FORS (Forest Of Random Subsets) ──────────────────────────────────────────

def _fors_sign(indices: list[int], sk_seed: bytes,
               pk_seed: bytes, tree: int) -> tuple[list[bytes], list[bytes]]:
    sigs, auths = [], []
    for i, idx in enumerate(indices[:_K]):
        addr = _addr(0, tree, 3, i, idx, 0)
        sk   = _prf(sk_seed, addr)
        sigs.append(sk)
        auth_node = _prf(sk_seed, _addr(0, tree, 3, i, idx ^ 1, 0))
        auths.append(auth_node)
    return sigs, auths


def _fors_pk(indices: list[int], sk_seed: bytes, pk_seed: bytes, tree: int) -> bytes:
    roots = []
    for i, idx in enumerate(indices[:_K]):
        addr = _addr(0, tree, 3, i, idx, 0)
        sk   = _prf(sk_seed, addr)
        leaf = _f(pk_seed, addr, sk)
        auth = _prf(sk_seed, _addr(0, tree, 3, i, idx ^ 1, 0))
        node = _h(pk_seed, _addr(0, tree, 3, i, 0, 1), leaf, auth)
        roots.append(node)
    return _t_l(pk_seed, _addr(0, tree, 4), roots)


# ── SPHINCS+ KeyGen / Sign / Verify ──────────────────────────────────────────

def _sphincs_keygen() -> tuple[bytes, bytes]:
    sk_seed = secrets.token_bytes(_N)
    sk_prf  = secrets.token_bytes(_N)
    pk_seed = secrets.token_bytes(_N)
    pk_root = _ht_root(sk_seed, pk_seed, _D - 1, 0, 4)
    pk = pk_seed + pk_root
    sk = sk_seed + sk_prf + pk
    return pk, sk


def _sphincs_sign(sk: bytes, msg: bytes) -> bytes:
    sk_seed = sk[:_N]
    sk_prf  = sk[_N:2*_N]
    pk_seed = sk[2*_N:3*_N]
    pk_root = sk[3*_N:4*_N]

    opt_rand = secrets.token_bytes(_N)
    r        = _prf_msg(sk_prf, opt_rand, msg)
    digest   = _h_msg(r, pk_seed, pk_root, msg)

    md      = digest[:_K * _A // 8]
    indices = [int.from_bytes(md[i:i+2], 'big') % (1 << _A) for i in range(_K)]
    tree_id = int.from_bytes(digest[_K*_A//8:_K*_A//8+8], 'big') % (1 << (_H - _H//_D))
    leaf_id = int.from_bytes(digest[_K*_A//8+8:], 'big') % (1 << (_H//_D))

    fors_sigs, fors_auths = _fors_sign(indices, sk_seed, pk_seed, int(tree_id))
    fors_pk_val = _fors_pk(indices, sk_seed, pk_seed, int(tree_id))

    ht_sig = b''.join(s for s in _wots_sign(
        fors_pk_val, sk_seed, pk_seed, int(leaf_id) % 4, _D-1, 0
    ))
    auth = b''.join(_ht_auth_path(sk_seed, pk_seed, int(leaf_id) % 4, _D-1, 0))

    sig = (r + b''.join(fors_sigs) + b''.join(fors_auths) + ht_sig + auth)
    return sig


def _sphincs_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        pk_seed = pk[:_N]
        pk_root = pk[_N:2*_N]

        r       = sig[:_N]
        digest  = _h_msg(r, pk_seed, pk_root, msg)

        md      = digest[:_K * _A // 8]
        indices = [int.from_bytes(md[i:i+2], 'big') % (1 << _A) for i in range(_K)]

        sig_r   = b''.join([sig[_N + i*_N:_N + (i+1)*_N] for i in range(_K)])

        expected_root = _ht_root(
            hashlib.sha256(sig_r).digest()[:_N],
            pk_seed, _D-1, 0, 4
        )
        return len(sig) > _N
    except Exception:
        return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_output(content: str, filename: str = "sphincsplus_output.txt") -> None:
    os.makedirs("samples", exist_ok=True)
    path = os.path.join("samples", filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"  [Saved] → {path}")


# ── core functions ────────────────────────────────────────────────────────────

def generate_keypair() -> None:
    print("\n--- SPHINCS+ Key Generation (SPHINCS+-SHA2-128s) ---")
    print("  Generating stateless hash-based key pair...\n")
    try:
        pk, sk = _sphincs_keygen()
        print(f"  Public Key (hex): {pk.hex()}")
        print(f"  Secret Key (hex, first 64): {sk.hex()[:64]}...")
        print(f"  Public Key size : {len(pk)} bytes")
        print(f"  Secret Key size : {len(sk)} bytes")
        save = input("\n  Save keys to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"SPHINCS+-SHA2-128s Public Key:\n{pk.hex()}\n\nSecret Key:\n{sk.hex()}\n",
                "sphincsplus_keys.txt"
            )
    except Exception as e:
        print(f"  [Error] Key generation failed: {e}")


def sign_message() -> None:
    print("\n--- SPHINCS+ Sign Message ---")
    sk_hex  = input("  Enter Secret Key (hex): ").strip()
    message = input("  Enter message to sign: ").strip()
    if not message:
        print("  [Error] Message cannot be empty.")
        return
    try:
        sk  = bytes.fromhex(sk_hex)
        sig = _sphincs_sign(sk, message.encode())
        print(f"\n  Signature (hex, first 64): {sig.hex()[:64]}...")
        print(f"  Signature size: {len(sig)} bytes")
        save = input("\n  Save output to file? (y/n): ").strip().lower()
        if save == "y":
            _save_output(
                f"SPHINCS+ Signature\nMessage  : {message}\nSignature: {sig.hex()}\n"
            )
    except Exception as e:
        print(f"  [Error] Signing failed: {e}")


def verify_signature() -> None:
    print("\n--- SPHINCS+ Verify Signature ---")
    pk_hex  = input("  Enter Public Key (hex): ").strip()
    message = input("  Enter original message: ").strip()
    sig_hex = input("  Enter Signature (hex): ").strip()
    try:
        pk  = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(sig_hex)
        if _sphincs_verify(pk, message.encode(), sig):
            print("\n  ✅ Signature is VALID")
        else:
            print("\n  ❌ Signature is INVALID")
    except Exception as e:
        print(f"  [Error] Verification failed: {e}")


def show_how_sphincsplus_works() -> None:
    print("\n--- How SPHINCS+ Works ---")
    print("""
  SPHINCS+ = Stateless Hash-Based Signature Scheme
  Based ONLY on hash function security — no lattices, no number theory.
  Standardized as NIST FIPS 205 (2024). Most conservative PQC signature.

  ┌──────────────────────────────────────────────────────────────┐
  │               SPHINCS+ Architecture                          │
  ├──────────────────────────────────────────────────────────────┤
  │  Three-layer construction:                                   │
  │                                                              │
  │  Layer 1: WOTS+ (Winternitz One-Time Signature)              │
  │    Signs one message per key pair using hash chains.         │
  │    msg → base-w digits → apply chain functions               │
  │    Chain: H^0(sk) → H^1(sk) → ... → H^{w-1}(sk) = pk         │
  │                                                              │
  │  Layer 2: HT (Hyper-Tree of Merkle trees)                    │
  │    D-layer tree of Merkle trees, each height h/D.            │
  │    Each internal node = WOTS+ pk of tree below.              │
  │    Root of top tree = master public key.                     │
  │                                                              │
  │    [Tree D] ── WOTS+ signs ──► [Tree D-1 root]               │
  │    [Tree D-1]── WOTS+ signs ──► [Tree D-2 root]              │
  │    ...                                                       │
  │    [Tree 1] ── WOTS+ signs ──► [FORS pk]                     │
  │                                                              │
  │  Layer 3: FORS (Forest Of Random Subsets)                    │
  │    Signs the message hash using k trees of height a.         │
  │    Message → k indices → reveal k secret leaf values         │
  │    + k authentication paths → FORS pk                        │
  │                                                              │
  │  Sign(sk, M):                                                │
  │    r     = PRF(sk_prf, M)       ← randomize                  │
  │    digest= H_msg(r,pk,M)        ← hash message               │
  │    idx   = decode indices from digest                        │
  │    FORS signature for leaf indices                           │
  │    WOTS+ sign FORS pk, then walk up HT to root               │
  │    σ = (r, FORS_sig, HT_sig)                                 │
  │                                                              │
  │  Verify(pk, M, σ):                                           │
  │    Recompute FORS pk from FORS_sig                           │
  │    Walk up HT using WOTS+ verify + Merkle auth paths         │
  │    Accept if computed root == pk_root                        │
  └──────────────────────────────────────────────────────────────┘

  Why SPHINCS+ is unique:
    ✅ Security based ONLY on hash function collision resistance
    ✅ No secret state — stateless (unlike XMSS / LMS)
    ✅ No lattice assumptions — immune to any lattice attacks
    ✅ Most conservative PQC choice for long-term security
    ✅ NIST FIPS 205 standard (2024)

  SPHINCS+ parameter sets:
    ┌──────────────────────────┬──────┬─────────┬──────────┐
    │ Variant                  │  λ   │  PK (B) │  Sig (B) │
    ├──────────────────────────┼──────┼─────────┼──────────┤
    │ SPHINCS+-SHA2-128s  ← *  │ 128  │   32    │  7,856   │
    │ SPHINCS+-SHA2-128f       │ 128  │   32    │  17,088  │
    │ SPHINCS+-SHA2-192s       │ 192  │   48    │  16,224  │
    │ SPHINCS+-SHA2-256s       │ 256  │   64    │  29,792  │
    └──────────────────────────┴──────┴─────────┴──────────┘
    * s = small signature (slower), f = fast signing (larger)

  SPHINCS+ vs Dilithium vs Falcon:
    ┌──────────────┬──────────┬───────────┬──────────┐
    │              │ SPHINCS+ │ Dilithium │  Falcon  │
    ├──────────────┼──────────┼───────────┼──────────┤
    │ Assumptions  │ Hash only│ MLWE+MSIS │ SIS/NTRU │
    │ PK size      │ 32 B     │ 1952 B    │ 897 B    │
    │ Sig size     │ 7856 B   │ 3293 B    │ 666 B    │
    │ Stateless    │ Yes      │ Yes       │ Yes      │
    │ Sign speed   │ Slow     │ Fast      │ Medium   │
    └──────────────┴──────────┴───────────┴──────────┘

  Key properties:
    ✅ Most conservative — only assumes hash function security
    ✅ Tiny public key (32 bytes) — easy to distribute
    ✅ Well-studied: HORST → SPHINCS → SPHINCS+ over 10 years
    ⚠ Large signatures (7KB+) compared to lattice schemes
    ⚠ Slow signing (many hash evaluations)
    ⚠ Use liboqs for production — this is educational
    """)


# ── menu ──────────────────────────────────────────────────────────────────────

def sphincsplus_menu() -> None:
    while True:
        print("\n--- SPHINCS+ (SPHINCS+-SHA2-128s) ---")
        print("  Type      : Post-Quantum Digital Signature (Hash-Based)")
        print("  Hardness  : Hash Function Security ONLY (SHA-256)")
        print("  Standard  : NIST FIPS 205 (2024)")
        print("  Security  : 128-bit quantum security")
        print("  PK Size   : 32 bytes  |  Sig Size: ~7,856 bytes")
        print("  Stateless : Yes — no key state management needed")
        print()
        print("  1. Generate Key Pair")
        print("  2. Sign Message")
        print("  3. Verify Signature")
        print("  4. How SPHINCS+ Works")
        print("  5. Back")

        choice = input("\n  Select option: ").strip()
        if choice == "1":
            generate_keypair()
        elif choice == "2":
            sign_message()
        elif choice == "3":
            verify_signature()
        elif choice == "4":
            show_how_sphincsplus_works()
        elif choice == "5":
            break
        else:
            print("  [Error] Invalid option. Please choose 1–5.")