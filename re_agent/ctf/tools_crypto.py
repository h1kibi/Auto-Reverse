"""
Crypto Recipe Tool - built-in RC4/XOR decryption.

LLM sees: 加密数据(..., 2) = RC4, key=Wrong!, ciphertext=0x...
Auto-Reverse executes: rc4_crypt → candidate → validator
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from ..core.observation import RuntimeObservation


class CryptoRecipe(BaseModel):
    algorithm: str = "rc4"
    key: str = ""
    key_encoding: str = "utf8"
    ciphertext_hex: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Pure Python RC4."""
    if not key:
        raise ValueError("empty RC4 key")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = 0
    j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def tool_crypto_recipe(args: dict) -> dict:
    try:
        recipe = CryptoRecipe.model_validate(args)
        key = bytes.fromhex(recipe.key) if recipe.key_encoding == "hex" else recipe.key.encode()
        data = bytes.fromhex(recipe.ciphertext_hex)

        if recipe.algorithm == "rc4":
            plain = rc4_crypt(key, data)
        elif recipe.algorithm == "xor":
            plain = bytes(b ^ key[0] for b in data) if len(key) == 1 else rc4_crypt(key, data)
        else:
            return RuntimeObservation(
                tool="crypto_recipe", status="skipped",
                summary=f"Unsupported algorithm: {recipe.algorithm}",
                structured={"algorithm": recipe.algorithm}, risk="read_only",
            ).model_dump()

        candidates = []
        try:
            text = plain.decode("utf-8")
            candidates.append({"value": text, "source": f"crypto_recipe:{recipe.algorithm}",
                                "confidence": 0.9})
        except UnicodeDecodeError:
            candidates.append({"value": plain.hex(), "source": f"crypto_recipe:{recipe.algorithm}:hex",
                                "confidence": 0.5})

        return RuntimeObservation(
            tool="crypto_recipe", status="ok",
            summary=f"{recipe.algorithm.upper()} decrypted {len(data)} bytes, {len(candidates)} candidate(s).",
            structured={"algorithm": recipe.algorithm, "ciphertext_len": len(data),
                        "plaintext_preview_hex": plain[:80].hex()},
            candidates=candidates, evidence_ids=recipe.evidence_ids,
            risk="read_only", token_hint=140,
        ).model_dump()

    except Exception as exc:
        return RuntimeObservation(
            tool="crypto_recipe", status="error",
            summary=f"Crypto recipe failed: {exc}", error=str(exc), risk="read_only",
        ).model_dump()
