"""ed25519（RFC 8032）纯标准库参考实现。

选型理由：AgentOS 阶段 1 坚持"零第三方依赖"，签名是账本 P2 的地基。
本实现为 RFC 8032 的直译版本，速度不重要（每次 run 只签 2-3 个事件），
正确性由 RFC 8032 官方测试向量保证（见 tests/test_harness.py）。
阶段 2 的 Rust agentd 使用 ed25519-dalek，格式互通。
"""

import hashlib

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


d = -121665 * _inv(121666) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = (4 * _inv(5)) % q
Bx = _xrecover(By)
B = [Bx % q, By % q]
IDENT = [0, 1]


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return IDENT
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P) -> bytes:
    return ((P[1] % q) | ((P[0] & 1) << 255)).to_bytes(32, "little")


def _decodepoint(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = q - x
    P = [x, y]
    if (-P[0] * P[0] + P[1] * P[1] - 1 - d * P[0] * P[0] * P[1] * P[1]) % q != 0:
        raise ValueError("decoding point that is not on curve")
    return P


def _secret_expand(sk: bytes) -> int:
    h = _H(sk)
    a = 2 ** (b - 2)
    for i in range(3, b - 2):
        a += 2 ** i * ((h[i // 8] >> (i % 8)) & 1)
    return a


def publickey(sk: bytes) -> bytes:
    """32 字节种子 → 32 字节公钥。"""
    return _encodepoint(_scalarmult(B, _secret_expand(sk)))


def signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """64 字节签名 = R(32) || S(32)。"""
    a = _secret_expand(sk)
    r = _H(h := _H(sk)[32:] + m)
    rr = int.from_bytes(r, "little") % l
    Renc = _encodepoint(_scalarmult(B, rr))
    k = int.from_bytes(_H(Renc + pk + m), "little") % l
    S = (rr + k * a) % l
    return Renc + _encodeint(S)


def checkvalid(sig: bytes, m: bytes, pk: bytes) -> bool:
    try:
        if len(sig) != 64 or len(pk) != 32:
            return False
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
        S = int.from_bytes(sig[32:], "little")
        if S >= l:
            return False
        k = int.from_bytes(_H(_encodepoint(R) + pk + m), "little") % l
        return _scalarmult(B, S) == _edwards_add(R, _scalarmult(A, k))
    except (ValueError, IndexError):
        return False
