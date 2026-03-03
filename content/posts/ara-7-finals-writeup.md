---
title: "ARA 7 Finals Write UP"
slug: "ara-7-finals-writeup"
date: 2026-03-03T21:42:36+07:00
draft: false
tags: ["ctf", "writeup", "cryptography", "ara7", "finals"]
categories: ["CTF", "Cryptography"]
author: "Ariq Ardian"
featureimage: "https://wallpapercave.com/wp/wp10095326.jpg"
params:
  math: true
---

{{< katex >}}

# Solve 1

# Crypto CTF Write-Up: `thesame`

Challenge endpoint:

```bash
nc chall-ctf.ara-its.id 9999
```

---

## Introduction

In this challenge, the server looks like a DSA-style signature service wrapped with a custom hash function. We are allowed to request signatures a few times, then we must submit a valid `(message, r, s)` tuple to pass access control.

At first glance, it seems fine. But after reading the source carefully, three issues chain together:

1. The signature nonce can be forced into a weak distribution.
2. The hash function is not a cryptographic hash; it is algebraic (`m^e mod n`) and leaks structure.
3. The access message validation can be bypassed with a simple modular trick.

That combination lets us recover the private key, invert the integrity target, forge a valid signature, and get the flag.

---

## 1) Understanding the Challenge Structure

From `release.py`:

- `q`: 1024-bit strong prime.
- `e`: 21-bit prime.
- `p` is generated as `p = e * k * q + 1` until prime.
- `g` is a generator of the subgroup of order `q` modulo `p`.
- private key `x` has 800 bits.

Signature equations:

$$
r = (g^k \bmod p) \bmod q
$$

$$
s = (h + x \cdot r)\cdot k^{-1} \bmod q
$$

Hash function:

$$
H(m) = m^e \bmod n,\;\; n = p\cdot q
$$

The first red flag is obvious: `H` is not a standard hash. It is modular exponentiation with algebraic structure.

---

## 2) First Vulnerability: Nonce Can Be Forced into a Weak Form

In the normal flow, after each successful signature, the next nonce is returned by `sign()`.

But there is an error branch when hex input is invalid:

```python
except ValueError:
    return False
...
else:
    k = randbelow(1 << (g%(e>>myfavnum))) + (1 << 1024)
```

So if we intentionally send invalid hex (`zz`) once, the next nonce has the form:

$$
k_i = 2^{1024} + t_i
$$

with `t_i` sampled from a range that is sometimes small enough for lattice recovery.

So the opening exploit strategy is:

1. enter sign menu,
2. send invalid hex to trigger weak-nonce path,
3. collect 4 controlled signatures afterward.

Why 4? We need enough equations to eliminate the private key and solve for small offsets.

---

## 3) Deriving Equations to Recover the Private Key `x`

For each signature `i`:

$$
s_i \cdot k_i \equiv h_i + x r_i \pmod q
$$

Substitute `k_i = K + t_i`, with `K = 2^{1024}`:

$$
s_i(K+t_i) \equiv h_i + x r_i \pmod q
$$

$$
s_i t_i - x r_i \equiv h_i - s_iK \pmod q
$$

Use signature 1 as reference and eliminate `x` between equations 1 and `i`:

$$
(r_i s_1)t_1 - (r_1 s_i)t_i \equiv r_1(s_iK-h_i) - r_i(s_1K-h_1)\pmod q
$$

Now we have linear congruences in the unknown small values (`t_1, t_2, t_3, t_4`). This is a Hidden Number Problem (HNP), solved with lattice methods (LLL + CVP).

In the solver, this becomes a 7x7 lattice:

- 3 components for congruence constraints modulo `q`,
- 4 components for the small variables `t_i`.

After CVP, we recover all `t_i`, then compute `x` directly:

$$
x \equiv (s_1(K+t_1)-h_1)\cdot r_1^{-1}\pmod q
$$

If this validates against all four signatures, `x` is correct.

---

## 4) Second Vulnerability: Algebraic Hash Leaks the Modulus

We request signatures on messages:

- `02`
- `04`
- `08`
- `10`

From signature output we get:

$$
h_2 = 2^e \bmod n,\;
h_4 = 4^e \bmod n,\;
h_8 = 8^e \bmod n,\;
h_{16}=16^e \bmod n
$$

Because all values are modulo `n`, differences like these are multiples of `n`:

$$
d_1 = h_2^2 - h_4,\quad
d_2 = h_2h_4 - h_8,\quad
d_3 = h_4^2 - h_{16}
$$

(and a few similar relations).

So:

$$
G = \gcd(d_1,d_2,d_3,\ldots)
$$

often yields `n` or a multiple of `n`.

Since each signature output also leaks `q`, we compute:

$$
p_{\text{mul}} = G / q
$$

Then clean extra factors using the public key relation. Because `y = g^x (mod p)` and `g` has order `q`:

$$
y^q \equiv 1 \pmod p
$$

Hence:

$$
p = \gcd(p_{\text{mul}}, y^q-1)
$$

Then:

$$
n = p\cdot q
$$

---

## 5) Recovering `e`

From generation logic:

$$
p-1 = e\cdot k \cdot q
$$

So `e` divides `(p-1)/q`, and `e` is a 21-bit prime.

We brute force 21-bit primes dividing `(p-1)/q`, then test:

$$
2^e \bmod n \stackrel{?}{=} h_2
$$

The matching candidate is the correct `e`.

---

## 6) Inverting `code integrity` (Finding a Preimage)

When choosing `g` menu, server prints:

```text
code integrity: T
```

where:

$$
T = H(access\_code) = access\_code^e \bmod n
$$

Our goal is to find `m` such that:

$$
m^e \equiv T \pmod n
$$

Compute root modulo `q`:

$$
m_q = T^{e^{-1}\bmod (q-1)} \bmod q
$$

For modulo `p`, because `p-1` contains factor `e`, solver uses:

$$
M = \frac{p-1}{e},\quad
m_p = T^{e^{-1}\bmod M} \bmod p
$$

Then combine with CRT:

$$
m_0 \equiv m_p \pmod p,\quad
m_0 \equiv m_q \pmod q
$$

so we get `m_0 (mod n)`.

---

## 7) Bypassing the Message Length Check

Server has this check:

```python
blen = 1 // (int(m_hex, 16) >> 511)
```

Effectively it forces the submitted message integer to satisfy `m >= 2^511`.

Bypass is simple: submit

$$
m = m_0 + n
$$

because:

$$
(m_0+n)^e \equiv m_0^e \equiv T \pmod n
$$

So modular hash value is unchanged, but message integer is larger and passes the bit-length gate.

---

## 8) Forging the Final Signature

After recovering private key `x`, we can also recover generator:

$$
g \equiv y^{x^{-1}\bmod q}\pmod p
$$

Choose random nonce `k`, then:

$$
r = (g^k \bmod p)\bmod q
$$

$$
s = (T + xr)\cdot k^{-1}\bmod q
$$

Submit tuple:

```text
(m_hex, r, s)
```

If everything is correct, server returns:

```text
ACCESS GRANTED!
ARA7{allow_allow_allow_allow_allow_access_granted}
```

---

## 9) Why Does the Solver Need Retries?

Even if we force the weak nonce branch, `t_i` is still random. Not every session gives `t_i` small enough for stable lattice recovery.

So the solver uses retry logic (`MAX_ATTEMPTS`) and quickly rejects bad sessions by checking:

- recovered `x` is in expected range,
- recovered `t_i` bit sizes are reasonable,
- reconstructed equations validate all signatures.

If checks fail, it reconnects and tries again.

---

## 10) Attack Summary in 7 Steps

1. Connect and read `pub: y`.
2. Trigger invalid hex once (`zz`) to force weak nonce path.
3. Collect 4 signatures for `02,04,08,10`.
4. Recover `x` using HNP lattice.
5. Recover `p,q,n,e` from algebraic hash structure.
6. Receive `T`, compute modular roots and rebuild `m` with CRT.
7. Forge `(r,s)` on `m`, submit, get flag.

---

## 11) Defensive Notes (Real-World Perspective)

To fix this in a real system:

- Use a real hash function (SHA-256, etc.), never `m^e mod n` as hash.
- Use strong CSPRNG nonce for signatures; no error branch should alter nonce distribution.
- Avoid leaking sensitive internals (like `q`) in signature output formats.
- Validate message format using proper encoding/padding rules, not only a bit-threshold check.

---

## 12) Challenge Source (`release.py`)

```python
from Crypto.Util.number import *
from secrets import *
import ast
import signal

myfavnum = 9

def gen_params():    
    q = getStrongPrime(1024)
    p = 4
    e = getPrime(21)
    while not isPrime(p):                
        k = randbits(1024) + (1 << 1024) 
        p = e * k * q + 1        
    a = (p - 1) // q 
    g = 1
    while g == 1:        
        h = randbelow(p - 3) + 2 
        g = pow(h, a, p)                         
    return (e, p, q, g, randbelow(q-1) + 1) 

def H(msg, e, n):         
    return pow(bytes_to_long(msg)%n, e, n)
    
def sign(params):
    e, m, p, q, g, x, k = params     
    n = p * q
    h = H(m, e, n)               
    r = pow(g, k, p) % q
    s = ((h + x * r) * pow(k, -1, q)) % q        
    return  (r, s, h, q), randbelow(1 << (g%(e>>myfavnum))) + (1 << 1024)


def verify(params):
    e, r, s, m, p, q, g, y = params
    if not (0 < r < q and 0 < s < q):
        return False
    h = H(m, e, p*q)
    try:
        w = pow(s, -1, q)
    except ValueError:
        return False
    u1 = (h * w) % q
    u2 = (r * w) % q    
    v = (pow(g, u1, p) * pow(y, u2, p)) % p
    v = v % q
    return v == r

def msg_sign(params):    
    try:
        msg = bytes.fromhex(input('sign what? (hex) : '))
    except ValueError:
        return False
    e, p, q, g, x, k = params        
    res, k = sign((e, msg, p, q, g, x, k))     
    print(res)
    return k

def check_access(params):
    e, p, q, g, y = params
    n = p * q     
    access_code = token_hex()    
    print(f"code integrity: {H(access_code.encode(),e,n)}") 
    try:
        m_hex, r, s = ast.literal_eval(input("access code and signature? ((m_hex, r, s)) : "))                
        blen = 1 // (int(m_hex, 16) >> 511)
        m = bytes.fromhex(m_hex) 
        r = int(r)
        s = int(s)        
    except:
        return False
    
    if verify((e, r, s, m, p, q, g, y)):          
        return H(m,e,n) == H(access_code.encode(), e, n)      

    return False

def main():    
    e, p, q, g, k = gen_params()    
    privkey = randbits(800) 
    y = pow(g, privkey, p)
    print(f"pub: {y}")
    remaining = list('ARA7!')
    while remaining:
        usr_input = input("sign or get access? (s/g/e for exit) : ").strip().lower()

        if usr_input == "s":
            new_k = msg_sign((e, p, q, g, privkey, k))

            if new_k:
                k = new_k
                remaining.pop()
            else:                                
                k = randbelow(1 << (g%(e>>myfavnum))) + (1 << 1024)
                print("Invalid message!")

        elif usr_input == "g":
            if check_access((e, p, q, g, y)):
                print("ACCESS GRANTED!")
            else:
                print("ACCESS DENIED! CHEAT DETECTED!")
            break

        elif usr_input == "e":
            print("Bye.")
            break

        else:
            print("Invalid input.")

    else:
        print("Thanks!")

if __name__ == "__main__":    
    signal.alarm(myfavnum)
    main()
```

---

## 13) Solver (`solver.py`)

```python
#!/usr/bin/env python3
from pwn import *
import math
import random
import re
from fpylll import IntegerMatrix, LLL, CVP
from Crypto.Util.number import inverse, isPrime

context.log_level = "debug"

HOST = args.HOST or "chall-ctf.ara-its.id"
PORT = int(args.PORT or 9999)
MAX_ATTEMPTS = int(args.MAX or 300)

K_NONCE = 1 << 1024
LATTICE_WEIGHT = 1 << 768


def sieve_primes(limit: int):
    table = bytearray(b"\x01") * (limit + 1)
    table[0:2] = b"\x00\x00"
    root = int(limit ** 0.5)
    for i in range(2, root + 1):
        if table[i]:
            start = i * i
            table[start : limit + 1 : i] = b"\x00" * (((limit - start) // i) + 1)
    return [i for i in range(2, limit + 1) if table[i]]


ALL_PRIMES = sieve_primes(1 << 21)
PRIMES_21 = [p for p in ALL_PRIMES if (1 << 20) <= p < (1 << 21)]
SMALL_PRIMES = [p for p in ALL_PRIMES if p < 10000]


def recv_pubkey(io):
    line = io.recvline(timeout=8.0)
    if not line:
        return None
    m = re.search(rb"pub:\s*(\d+)", line)
    if not m:
        return None
    return int(m.group(1))


def get_signature(io, msg_hex: bytes):
    io.sendlineafter(b"sign or get access? (s/g/e for exit) : ", b"s")
    io.sendlineafter(b"sign what? (hex) : ", msg_hex)
    line = io.recvline(timeout=1.0)
    if not line:
        return None
    vals = re.findall(rb"\d+", line)
    if len(vals) < 4:
        return None
    r, s, h, q = map(int, vals[:4])
    return r, s, h, q


def recover_x_and_t(signatures, q):
    r1, s1, h1 = signatures[0]
    rows = []
    c_vals = []
    for i in range(1, 4):
        ri, si, hi = signatures[i]
        a = (ri * s1) % q
        b = (-r1 * si) % q
        c = (r1 * (si * K_NONCE - hi) - ri * (s1 * K_NONCE - h1)) % q
        row = [0, 0, 0, 0]
        row[0] = a
        row[i] = b
        rows.append(row)
        c_vals.append(c)

    # CVP lattice for solving small-offset nonces t_i in:
    #   (ri*s1)t1 - (r1*si)ti = c_i (mod q)
    mat = IntegerMatrix(7, 7)
    for i in range(3):
        mat[i, i] = q * LATTICE_WEIGHT
    for col, row in enumerate(rows):
        for idx, v in enumerate(row):
            mat[3 + idx, col] = v * LATTICE_WEIGHT
    for i in range(4):
        mat[3 + i, 3 + i] = 1

    LLL.reduction(mat)
    target = [c * LATTICE_WEIGHT for c in c_vals] + [0, 0, 0, 0]
    closest = CVP.closest_vector(mat, target)

    t_vals = [int(closest[3 + i]) for i in range(4)]
    x = (signatures[0][1] * (K_NONCE + t_vals[0]) - signatures[0][2]) * inverse(signatures[0][0], q) % q

    for (r, s, h), t in zip(signatures, t_vals):
        if (s * (K_NONCE + t) - h - x * r) % q != 0:
            return None, None

    return x, t_vals


def recover_p_and_n(y, q, h2, h4, h8, h16):
    diffs = [
        abs(h2 * h2 - h4),
        abs(h2 * h4 - h8),
        abs(h2 * h8 - h16),
        abs(h4 * h4 - h16),
        abs(pow(h2, 3) - h8),
        abs(pow(h2, 4) - h16),
    ]

    g = 0
    for d in diffs:
        g = d if g == 0 else math.gcd(g, d)

    if g == 0 or g % q != 0:
        return None, None

    p_mul = g // q
    p = math.gcd(p_mul, pow(y, q, p_mul) - 1)
    for sp in SMALL_PRIMES:
        while p % sp == 0 and p // sp > 1:
            p //= sp

    if p <= 1 or not isPrime(p):
        return None, None

    return p, p * q


def recover_e(p, q, n, h2):
    cofactor = (p - 1) // q
    for pr in PRIMES_21:
        if cofactor % pr == 0 and pow(2, pr, n) == h2:
            return pr
    return None


def crt(a, b, m, n):
    t = ((b - a) * inverse(m, n)) % n
    return a + t * m


def even_hex(x: int):
    hx = f"{x:x}"
    if len(hx) & 1:
        hx = "0" + hx
    return hx


def forge_attempt():
    io = process(["python3", "release.py"], stdin=PIPE, stdout=PIPE, stderr=PIPE) if args.LOCAL else remote(HOST, PORT)
    try:
        y = recv_pubkey(io)
        if y is None:
            return False, b""

        # Force first nonce into the weak distribution path.
        io.sendlineafter(b"sign or get access? (s/g/e for exit) : ", b"s")
        io.sendlineafter(b"sign what? (hex) : ", b"zz")
        io.recvline(timeout=0.5)

        sigs = []
        q = None
        for msg_hex in (b"02", b"04", b"08", b"10"):
            sig = get_signature(io, msg_hex)
            if sig is None:
                return False, b""
            r, s, h, qi = sig
            if q is None:
                q = qi
            sigs.append((r, s, h))

        x, t_vals = recover_x_and_t(sigs, q)
        if x is None:
            return False, b""

        # Fast reject non-exploitable sessions.
        if x.bit_length() > 800:
            return False, b""
        if max(abs(t).bit_length() for t in t_vals) > 760:
            return False, b""

        h2, h4, h8, h16 = [h for (_, _, h) in sigs]
        p, n = recover_p_and_n(y, q, h2, h4, h8, h16)
        if p is None:
            return False, b""

        e = recover_e(p, q, n, h2)
        if e is None:
            return False, b""

        g = pow(y, inverse(x, q), p)
        for (r, _, _), t in zip(sigs, t_vals):
            if pow(g, K_NONCE + t, p) % q != r:
                return False, b""

        io.sendlineafter(b"sign or get access? (s/g/e for exit) : ", b"g")
        line = io.recvline(timeout=1.0)
        if not line:
            return False, b""
        m = re.search(rb"code integrity:\s*(\d+)", line)
        if not m:
            return False, b""
        target = int(m.group(1))

        if math.gcd(e, q - 1) != 1:
            return False, b""
        m_part = (p - 1) // e
        if math.gcd(e, m_part) != 1:
            return False, b""

        root_q = pow(target % q, inverse(e, q - 1), q)
        root_p = pow(target % p, inverse(e, m_part), p)
        if pow(root_q, e, q) != target % q or pow(root_p, e, p) != target % p:
            return False, b""

        root_n = crt(root_p, root_q, p, q) % n
        forged_m = root_n + n  # pass the >= 2^511 gate while preserving H(m).
        forged_m_hex = even_hex(forged_m)

        while True:
            k = random.randrange(1, q)
            r = pow(g, k, p) % q
            if r == 0:
                continue
            s = ((target + x * r) * inverse(k, q)) % q
            if s == 0:
                continue
            break

        payload = str((forged_m_hex, int(r), int(s))).encode()
        io.sendlineafter(b"access code and signature? ((m_hex, r, s)) : ", payload)
        out = io.recvall(timeout=1.5)
        return (b"ACCESS GRANTED!" in out), out
    except Exception:
        return False, b""
    finally:
        io.close()


def main():
    for attempt in range(1, MAX_ATTEMPTS + 1):
        log.info(f"Attempt {attempt}/{MAX_ATTEMPTS}")
        ok, out = forge_attempt()
        if not ok:
            continue

        text = out.decode(errors="ignore")
        m = re.search(r"([A-Za-z0-9_]+\{[^}]+\})", text)
        flag = m.group(1) if m else text.strip()
        log.success(f"Flag Recovered: {flag}")
        return

    log.failure("Exploit did not succeed within max attempts.")


if __name__ == "__main__":
    main()
```

---

## 14) How to Run the Solver

```bash
python3 solver.py
```

If you want more retries:

```bash
python3 solver.py MAX=300
```

---

## 15) Final Result

Flag:

```text
ARA7{allow_allow_allow_allow_allow_access_granted}
```


---

# Solve 2

# Crypto Challenge Write-up (Phase 1 + Phase 2)

Title : Bloom in Two

This write-up explains how to solve the challenge in `chall.py` using the method implemented in `solver.py`.
I will keep the language simple and focus on the exact math that makes the solve work.

---

## 1. Quick map of the challenge

The challenge has **two phases**:

1. **Phase 1**: recover RSA private exponent `d` from partial leak (`d_hi`) and use it to decrypt 3 ciphertexts.
2. **Phase 2**: recover hidden vector `B` from masked linear leaks, then submit:
   `sha256(','.join(map(str, B)))`.

If both phases are solved, server prints the flag.

---

## 2. Read important parts of `chall.py`

In `bloom_in_two(...)`, key generation is unusual:

- `p = 2*g*a + 1`
- `q = 2*g*b + 1`
- `N = p*q`
- `lcm = 2*g*a*b`
- `d` is a 128-bit prime (`d_bits = 0.25 * 512 = 128`)
- `e = d^{-1} mod lcm`

Then challenge leaks:

- `N`
- `e`
- `d_hi = d >> 52`
- `d_lo` (but here `l = 0`, so `d_lo` is always `0`, not useful)

So we know high bits of `d`, and only **52 low bits** are missing.

---

## 3. Phase 1 attack idea

### 3.1 Known/unknown split of `d`

We write:

$$
d = D + x,
\quad D = d_{hi} \cdot 2^{52},
\quad 0 \le x < 2^{52}
$$

Also `d` is an odd prime, so `x` is odd.

### 3.2 Use RSA relation in exponent form

Because `e` is inverse of `d` modulo `lcm`, we have:

$$
e d \equiv 1 \pmod{\lambda}
$$

and for any `z` with `gcd(z, N)=1`:

$$
z^{ed-1} \equiv 1 \pmod N
$$

Substitute `d = D + x`:

$$
z^{e(D+x)-1} \equiv 1 \pmod N
$$

Move known part to the other side:

$$
z^{ex} \equiv z^{-(eD-1)} \pmod N
$$

### 3.3 Remove oddness with `x = 2y+1`

Because `x` is odd:

$$
x = 2y + 1,
\quad 0 \le y < 2^{51}
$$

Then:

$$
(z^{2e})^y \equiv z^{-(e(D+1)-1)} \pmod N
$$

Define:

$$
G = z^{2e} \bmod N,
\quad H = z^{-(e(D+1)-1)} \bmod N
$$

Now problem becomes interval discrete log:

$$
G^y \equiv H \pmod N,
\quad y \in [0, 2^{51})
$$

### 3.4 Solve interval DLP with Pollard Kangaroo

`solver.py` uses multi-process kangaroo (`kangaroo_worker`) to find `y` in that range.
Complexity is about square-root interval:

$$
\tilde{O}(\sqrt{2^{51}}) = \tilde{O}(2^{25.5})
$$

After `y` is found:

$$
x = 2y + 1,
\quad d = D + x
$$

`solver.py` checks candidate with:

```python
pow(2, e*d - 1, N) == 1
```

If true, `d` is correct.

### 3.5 Use recovered `d` to pass 3 rounds

Server sends `ct_m = m^e mod N`.
We decrypt with recovered `d`:

$$
m = ct_m^d \bmod N
$$

Send integer `m` back 3 times, Phase 1 done.

---

## 4. Phase 2 attack idea

Now server creates:

- prime `q` (256-bit)
- secret vector `B = [B_0,...,B_9]`, each in `[1, q-1]`
- 36 rounds with user-chosen `token`

For each round `i`:

1. server derives `(coeffs_i, pad_i, mask_i)` using `derive(salt, i, token)`
2. computes:

$$
mix_i = \left(\sum_{j=0}^{9} c_{i,j} B_j\right) \bmod q
$$

3. computes truncated leak:

$$
leak_i = \left\lfloor \frac{(mix_i + pad_i) \bmod q}{2^8} \right\rfloor
$$

4. returns:

$$
echo_i = leak_i \oplus mask_i
$$

### 4.1 Why attacker can unmask

We choose `token`, and `salt` is public.
So we can run the same `derive(...)` locally and know `coeffs_i`, `pad_i`, `mask_i` exactly.
Then:

$$
leak_i = echo_i \oplus mask_i
$$

So mask is not security here.

### 4.2 Build bounded equations

From the shift operation, there exists remainder `r_i` with `0 <= r_i < 256` such that:

$$
(mix_i + pad_i) \bmod q = 256 \cdot leak_i + r_i
$$

Let:

$$
t_i = 256 \cdot leak_i - pad_i
$$

Then for some integer `k_i`:

$$
\sum_{j=0}^{9} c_{i,j} B_j - qk_i - t_i = r_i,
\quad 0 \le r_i < 256
$$

This is exactly the core constraint used by `solver.py`.

Vector form (36 equations):

$$
A B - T = qK + R,
\quad R \in [0,255]^{36}
$$

Where:

- `A` is 36x10 matrix of coefficients
- `B` is secret length-10 vector
- `T` is known vector from leaks/pads
- `K` is integer vector (unknown)
- `R` is small bounded noise vector

### 4.3 How `solver.py` solves Phase 2

`solver.py` tries lattice first (`solve_phase2_lattice`):

1. Build lattice:

$$
L = \{ qz + Ax \mid z \in \mathbb{Z}^{36},\ x \in \mathbb{Z}^{10} \}
$$

2. Find lattice point `l` close to target `T` so that:

$$
l - T \in [0,255]^{36}
$$

3. Recover `B` from modular system:

$$
AB \equiv l \pmod q
$$

using Gaussian elimination mod `q` (`solve_linear_mod_q`).

4. Verify all row constraints and bounds `1 <= B_j < q`.

If lattice path fails, solver falls back to Z3 (`solve_phase2_z3`) with direct integer constraints:

$$
0 \le \sum_j c_{i,j}B_j - qK_i - t_i < 256
$$

for all 36 rows.

---

## 5. Final step to get flag

Once `B` is recovered, compute digest exactly like server:

$$
digest = \mathrm{SHA256}(B_0,B_1,\ldots,B_9)
$$

More precisely (same serialization):

```python
hashlib.sha256(",".join(str(x) for x in B).encode()).hexdigest()
```

Send this `digest` and server returns flag.

---

## 6. Full exploit flow (practical)

1. Receive `N, e, d_hi`.
2. Set `D = d_hi << 52`.
3. Convert unknown low part into interval DLP and solve with kangaroo to get `y`.
4. Rebuild `d = D + 2*y + 1`.
5. Decrypt 3 ciphertexts with `m = ct^d mod N` and send answers.
6. In Phase 2, for each round pick random 64-bit token.
7. Recompute `coeffs,pad,mask` locally, unmask `leak`, build `t_i`.
8. Solve bounded linear system (lattice/Z3) to recover `B`.
9. Send SHA-256 digest of comma-joined `B` values.
10. Get flag.

---

## 7. Why this challenge is breakable

Main weakness is not one bug, but combination:

- **Phase 1** leaks almost all bits of `d` (only 52 unknown bits).
- RSA relation lets us rewrite unknown bits into an **interval discrete log** problem.
- **Phase 2** mask is predictable because attacker controls `token` and sees `salt`.
- Remaining unknowns become a solvable bounded linear system with many samples (36 equations for 10 secret values).

That is enough for a full solve from public interaction only.

---

## 8. Copy-ready key formulas (LaTeX)

$$
d = d_{hi} \cdot 2^{52} + x,
\quad 0 \le x < 2^{52},
\quad x = 2y+1
$$

$$
z^{e(D+x)-1} \equiv 1 \pmod N
\Rightarrow
(z^{2e})^y \equiv z^{-(e(D+1)-1)} \pmod N
$$

$$
mix_i = \left(\sum_{j=0}^{9} c_{i,j} B_j\right) \bmod q
$$

$$
leak_i = \left\lfloor \frac{(mix_i + pad_i) \bmod q}{256} \right\rfloor
$$

$$
\sum_{j=0}^{9} c_{i,j} B_j - qk_i - (256\cdot leak_i - pad_i) = r_i,
\quad 0 \le r_i < 256
$$

$$
A B - T = qK + R,
\quad R \in [0,255]^{36}
$$



---

## 9. Full Source: `chall.py`

```python
from Crypto.Util.number import *
import hashlib, os, random, signal

flag = open("flag.txt", "rb").read().strip()

N_BITS = 512

def bloom_in_two(nbits, growth, hm, hm1, hm2):
    seed_bits = int(nbits * growth)
    d_bits = int(nbits * hm)
    m = int(nbits * hm1)
    l = int(nbits * hm2)
    hehe = d_bits - m - l
    if hehe <= 0:
        raise ValueError("?")

    a_bits = (nbits // 2) - seed_bits - 1
    if a_bits <= 32:
        raise ValueError("?")

    e_low = int(0.70 * nbits)
    e_high = int(0.74 * nbits)

    while True:
        g = getPrime(seed_bits)

        while True:
            a = random.getrandbits(a_bits)
            if a < (1 << (a_bits - 1)):
                continue
            p = 2 * g * a + 1
            if isPrime(p):
                break

        while True:
            b = random.getrandbits(a_bits)
            if b < (1 << (a_bits - 1)) or b == a:
                continue
            if GCD(a, b) != 1:
                continue
            q = 2 * g * b + 1
            if isPrime(q):
                break

        N = p * q
        lcm = 2 * g * a * b
        d = getPrime(d_bits)
        if GCD(d, lcm) != 1:
            continue

        e = inverse(d, lcm)
        if not (e_low <= e.bit_length() <= e_high):
            continue

        d_hi = d >> (hehe + l)
        d_lo = d & ((1 << l) - 1)

        return {
            "N": N,
            "e": e,
            "d": d,
            "d_bits": d_bits,
            "m": m,
            "l": l,
            "hehe": hehe,
            "d_hi": d_hi,
            "d_lo": d_lo,
        }

def gen(n, m, coeff_bits, mod_bits, big_bits, shift):
    q = getPrime(mod_bits)
    B = [random.randrange(1 << (big_bits - 1), 1 << big_bits) for _ in range(n)]

    rows = []
    while len(rows) < m:
        coeffs = [random.randint(-(1 << coeff_bits), 1 << coeff_bits) for _ in range(n)]
        if all(c == 0 for c in coeffs):
            continue
        t = sum(c * b for c, b in zip(coeffs, B)) % q
        r = t >> shift
        rows.append((coeffs, r))

    digest = hashlib.sha256(",".join(str(x) for x in B).encode()).hexdigest()
    return q, rows, digest

def derive(salt_hex, idx, token, n, coeff_bits, shift):
    seed = f"{salt_hex}|{idx}|{token}".encode()
    stream = hashlib.shake_256(seed).digest(4 * n + 16)
    span = 1 << coeff_bits

    coeffs = []
    ptr = 0
    for _ in range(n):
        x = int.from_bytes(stream[ptr : ptr + 4], "big")
        ptr += 4
        coeffs.append((x % (2 * span + 1)) - span)

    pad_raw = int.from_bytes(stream[ptr : ptr + 8], "big")
    mask_raw = int.from_bytes(stream[ptr + 8 : ptr + 16], "big")
    pad = pad_raw & ((1 << shift) - 1)
    mask = mask_raw & ((1 << 48) - 1)
    return coeffs, pad, mask

def main():
    inst = bloom_in_two(N_BITS, 0.28, 0.25, 0.15, 0.0)

    print("[phase 1]")
    print("N =", inst["N"])
    print("e =", inst["e"])
    print("d_hi =", inst["d_hi"])
    print("d_lo =", inst["d_lo"])

    for i in range(3):
        print(f"round {i + 1}/{3}")
        target_str = os.urandom(16).hex()
        m = bytes_to_long(target_str.encode())
        ct_m = pow(m, inst["e"], inst["N"])
        print("ct_m =", ct_m)
        guess = int(input("guess = ").strip())
        if guess != m:
            print("wrong")
            os._exit(0)
        print("ok")

    print("[phase 2]")
    shift = 8
    q = getPrime(256)
    B = [random.randrange(1, q) for _ in range(10)]
    digest = hashlib.sha256(",".join(str(x) for x in B).encode()).hexdigest()
    salt_hex = os.urandom(12).hex()
    print("q =", q)
    print("shift =", shift)
    print("n =", 10)
    print("samples =", 36)
    print("salt =", salt_hex)
    for i in range(36):
        token = int(input("tune = ").strip())
        token &= (1 << 64) - 1
        coeffs, pad, mask = derive(salt_hex, i, token, 10, 8, shift)
        mix = sum(c * b for c, b in zip(coeffs, B)) % q
        leak = ((mix + pad) % q) >> shift
        echo = leak ^ mask
        print("echo =", echo)

    print("submit sha256(','.join(map(str, B)))")
    ans = input("digest = ").strip().lower()
    if ans != digest:
        print("wrong")
        os._exit(0)

    print("nice :3")
    print(flag)

if __name__ == "__main__":
    signal.alarm(67)
    try:
        main()
    except Exception as e:
        print(e.__class__)
```

## 10. Full Source: `solver.py`

```python
#!/usr/bin/env python3
import hashlib
import math
import multiprocessing as mp
import os
import random
import re
import sys
from typing import List, Optional, Tuple

import gmpy2
import z3
from pwn import *

context.log_level = "debug"

HOST = os.environ.get("HOST", "chall-ctf.ara-its.id")
PORT = int(os.environ.get("PORT", "2407"))

# Phase-1 constants from challenge construction
UNKNOWN_LOW_BITS = 52
Y_BITS = UNKNOWN_LOW_BITS - 1  # x is odd => x = 2*y+1
Y_RANGE = 1 << Y_BITS

try:
    import sympy as sp
    from sympy.matrices.normalforms import hermite_normal_form
    from fpylll import CVP, IntegerMatrix, LLL

    HAVE_LATTICE_PHASE2 = True
except Exception:
    HAVE_LATTICE_PHASE2 = False


def parse_int(line: bytes) -> int:
    return int(line.split(b"=", 1)[1].strip())


def derive(salt_hex: str, idx: int, token: int, n: int = 10, coeff_bits: int = 8, shift: int = 8):
    seed = f"{salt_hex}|{idx}|{token}".encode()
    stream = hashlib.shake_256(seed).digest(4 * n + 16)
    span = 1 << coeff_bits

    coeffs = []
    ptr = 0
    for _ in range(n):
        x = int.from_bytes(stream[ptr : ptr + 4], "big")
        ptr += 4
        coeffs.append((x % (2 * span + 1)) - span)

    pad_raw = int.from_bytes(stream[ptr : ptr + 8], "big")
    mask_raw = int.from_bytes(stream[ptr + 8 : ptr + 16], "big")
    pad = pad_raw & ((1 << shift) - 1)
    mask = mask_raw & ((1 << 48) - 1)
    return coeffs, pad, mask


def jump_index(v: gmpy2.mpz, mask: int) -> int:
    # Mixed-limb hash to avoid low-bit cycle artifacts.
    t = v ^ (v >> 64) ^ (v >> 128) ^ (v >> 192) ^ (v >> 256) ^ (v >> 320)
    return int(t & mask)


def kangaroo_worker(seed: int, base: int, N: int, e: int, D: int, conn):
    try:
        Nmp = gmpy2.mpz(N)
        z = base
        if gmpy2.gcd(z, Nmp) != 1:
            z += 2

        # Equation: (z^(2e))^y = z^(-(e*(D+1)-1))
        A = e * (D + 1) - 1
        G = gmpy2.powmod(z, 2 * e, Nmp)
        H = gmpy2.powmod(z, -A, Nmp)

        sqrtW = int(math.isqrt(Y_RANGE))
        B = Y_RANGE - 1

        k = 64
        rng = random.Random(seed)
        jumps = [(rng.randrange(max(2, sqrtW // 2), sqrtW * 2) | 1) for _ in range(k)]
        Gpow = [gmpy2.powmod(G, s, Nmp) for s in jumps]
        mask = k - 1

        Nt = sqrtW

        yt = gmpy2.powmod(G, B, Nmp)
        Dt = B
        for _ in range(Nt):
            j = jump_index(yt, mask)
            yt = (yt * Gpow[j]) % Nmp
            Dt += jumps[j]

        yw = H
        Dw = 0
        limit = Dt + B + max(jumps)

        while Dw <= limit:
            j = jump_index(yw, mask)
            yw = (yw * Gpow[j]) % Nmp
            Dw += jumps[j]
            if yw == yt:
                y = Dt - Dw
                if 0 <= y < Y_RANGE and gmpy2.powmod(G, y, Nmp) == H:
                    conn.send(int(y))
                else:
                    conn.send(None)
                conn.close()
                return

        conn.send(None)
        conn.close()
    except Exception:
        try:
            conn.send(None)
            conn.close()
        except Exception:
            pass


def recover_d(N: int, e: int, d_hi: int, timeout: int = 66) -> int:
    D = d_hi << UNKNOWN_LOW_BITS

    workers = []
    conns = []
    seeds = [1000, 1001, 1002, 1003]
    bases = [2, 3, 5, 7]

    for seed, base in zip(seeds, bases):
        p_conn, c_conn = mp.Pipe(False)
        p = mp.Process(target=kangaroo_worker, args=(seed, base, N, e, D, c_conn))
        p.start()
        c_conn.close()
        workers.append(p)
        conns.append(p_conn)

    found_y = None
    deadline = time.time() + timeout
    while time.time() < deadline and any(p.is_alive() for p in workers):
        ready = mp.connection.wait(conns, timeout=0.2)
        for c in ready:
            try:
                r = c.recv()
            except EOFError:
                r = None
            if r is not None:
                found_y = r
                break
        if found_y is not None:
            break

    for p in workers:
        if p.is_alive():
            p.terminate()
    for p in workers:
        p.join()

    if found_y is None:
        raise RuntimeError("Phase-1 dlog failed or timed out")

    x = 2 * found_y + 1
    d = D + x
    # Quick correctness check
    if pow(2, e * d - 1, N) != 1:
        raise RuntimeError("Recovered d candidate failed consistency check")
    return d


def solve_linear_mod_q(A: List[List[int]], b: List[int], q: int) -> Optional[List[int]]:
    # Gaussian elimination over F_q for an overdetermined linear system.
    m = len(A)
    n = len(A[0])
    M = [[A[i][j] % q for j in range(n)] + [b[i] % q] for i in range(m)]

    r = 0
    pivots = []
    for c in range(n):
        pivot = None
        for i in range(r, m):
            if M[i][c] % q != 0:
                pivot = i
                break
        if pivot is None:
            continue

        M[r], M[pivot] = M[pivot], M[r]
        inv = pow(M[r][c], -1, q)
        for j in range(c, n + 1):
            M[r][j] = (M[r][j] * inv) % q

        for i in range(m):
            if i == r:
                continue
            f = M[i][c] % q
            if f != 0:
                for j in range(c, n + 1):
                    M[i][j] = (M[i][j] - f * M[r][j]) % q

        pivots.append(c)
        r += 1
        if r == n:
            break

    if r < n:
        return None

    for i in range(r, m):
        if M[i][n] % q != 0:
            return None

    x = [0] * n
    for i, c in enumerate(pivots):
        x[c] = M[i][n] % q
    return x


def solve_phase2_lattice(q: int, rows: List[Tuple[List[int], int]]) -> Optional[List[int]]:
    if not HAVE_LATTICE_PHASE2:
        return None

    m = len(rows)
    n = len(rows[0][0])
    A = [coeffs[:] for coeffs, _ in rows]
    T = [t for _, t in rows]

    # L = {q*z + A*x}. Build a square HNF basis from generators [q*I ; A_cols].
    gens = []
    for i in range(m):
        row = [0] * m
        row[i] = q
        gens.append(row)
    for j in range(n):
        gens.append([A[i][j] for i in range(m)])

    try:
        hnf_cols = hermite_normal_form(sp.Matrix(gens).T)
    except Exception:
        return None

    basis_rows = hnf_cols.T
    if basis_rows.rows != m or basis_rows.cols != m:
        return None

    basis = IntegerMatrix(m, m)
    for i in range(m):
        for j in range(m):
            basis[i, j] = int(basis_rows[i, j])

    LLL.reduction(basis)

    # Solve "point in box": find l in L with l - T in [0,255]^m.
    shifts = (0, 128, 64, 192, 32, 224, 16, 240)
    candidates = {}

    for sh in shifts:
        target = [t + sh for t in T]
        try:
            l = CVP.closest_vector(basis, target)
        except Exception:
            continue

        U = [int(l[i] - T[i]) for i in range(m)]
        if any(u < 0 or u >= 256 for u in U):
            continue

        Bvals = solve_linear_mod_q(A, [int(l[i] % q) for i in range(m)], q)
        if Bvals is None:
            continue
        if any(b <= 0 or b >= q for b in Bvals):
            continue

        ok = True
        for i, (coeffs, t) in enumerate(rows):
            if (sum(coeffs[j] * Bvals[j] for j in range(n)) - t) % q != U[i]:
                ok = False
                break
        if not ok:
            continue

        key = tuple(Bvals)
        candidates[key] = candidates.get(key, 0) + 1

    if not candidates:
        return None

    best = max(candidates.items(), key=lambda kv: kv[1])[0]
    return list(best)


def solve_phase2_z3(q: int, rows: List[Tuple[List[int], int]], timeout_ms: int = 8000) -> Optional[List[int]]:
    Bs = [z3.Int(f"B{i}") for i in range(10)]
    Ks = [z3.Int(f"K{i}") for i in range(len(rows))]

    s = z3.Solver()
    s.set(timeout=timeout_ms)

    for b in Bs:
        s.add(b >= 1, b < q)

    for i, (coeffs, t) in enumerate(rows):
        expr = sum(coeffs[j] * Bs[j] for j in range(10)) - q * Ks[i] - t
        s.add(expr >= 0, expr < 256)

        # Tight per-row k bounds from coefficient signs and B range [1, q-1].
        smin = 0
        smax = 0
        for c in coeffs:
            if c >= 0:
                smin += c * 1
                smax += c * (q - 1)
            else:
                smin += c * (q - 1)
                smax += c * 1
        klo = (smin - t - 255 + q - 1) // q
        khi = (smax - t) // q
        s.add(Ks[i] >= klo - 2, Ks[i] <= khi + 2)

    if s.check() != z3.sat:
        return None

    m = s.model()
    return [m[b].as_long() for b in Bs]


def solve_phase2(q: int, rows: List[Tuple[List[int], int]], timeout_ms: int = 8000) -> Optional[List[int]]:
    Bvals = solve_phase2_lattice(q, rows)
    if Bvals is not None:
        return Bvals

    log.warning("Lattice phase-2 solver unavailable/failed, falling back to Z3")
    return solve_phase2_z3(q, rows, timeout_ms=timeout_ms)


def is_hex_ascii_payload(v: int) -> bool:
    b = long_to_bytes(v)
    if len(b) != 32:
        return False
    return all((0x30 <= x <= 0x39) or (0x61 <= x <= 0x66) for x in b)


def main():
    io = remote(HOST, PORT)

    io.recvuntil(b"N = ")
    N = int(io.recvline().strip())
    io.recvuntil(b"e = ")
    e = int(io.recvline().strip())
    io.recvuntil(b"d_hi = ")
    d_hi = int(io.recvline().strip())
    io.recvuntil(b"d_lo = ")
    _ = int(io.recvline().strip())

    log.info("Recovering phase-1 private exponent... this is the expensive step")
    d = recover_d(N, e, d_hi)
    log.success(f"Recovered d (bits={d.bit_length()})")

    # Phase 1 rounds
    for r in range(3):
        io.recvuntil(b"ct_m = ")
        ct = int(io.recvline().strip())
        m = pow(ct, d, N)
        if not is_hex_ascii_payload(m):
            raise RuntimeError("Decryption sanity failed in phase 1")
        io.sendlineafter(b"guess = ", str(m).encode())
        line = io.recvline().strip()
        if line != b"ok":
            raise RuntimeError(f"Phase-1 round failed: {line!r}")

    # Phase 2 header
    io.recvuntil(b"q = ")
    q = int(io.recvline().strip())
    io.recvuntil(b"shift = ")
    shift = int(io.recvline().strip())
    io.recvuntil(b"n = ")
    n = int(io.recvline().strip())
    io.recvuntil(b"samples = ")
    samples = int(io.recvline().strip())
    io.recvuntil(b"salt = ")
    salt_hex = io.recvline().strip().decode()

    rows = []
    for i in range(samples):
        token = random.getrandbits(64)
        coeffs, pad, mask = derive(salt_hex, i, token, n=n, coeff_bits=8, shift=shift)
        io.sendlineafter(b"tune = ", str(token).encode())
        io.recvuntil(b"echo = ")
        echo = int(io.recvline().strip())
        leak = echo ^ mask
        t = (leak << shift) - pad
        rows.append((coeffs, t))

    io.recvuntil(b"digest = ")
    log.info("Solving phase-2 integer system...")
    Bvals = solve_phase2(q, rows, timeout_ms=8000)
    if Bvals is None:
        raise RuntimeError("Phase-2 solver timed out/unsat in current attempt")

    digest = hashlib.sha256(",".join(str(x) for x in Bvals).encode()).hexdigest()
    io.sendline(digest.encode())

    rest = io.recvall(timeout=3)
    print(rest.decode(errors="ignore"))


if __name__ == "__main__":
    import time
    from Crypto.Util.number import long_to_bytes

    main()

```

---

## 11. Final Result

Flag:

```text
ARA7{fyi_aja_ini_chall_harusnya_buat_quals_WKWKWKWKWKWK_yaaa_semoga_ga_segampang_itu_yang_penting_ga_pure_sloppable_:sob:}
```
