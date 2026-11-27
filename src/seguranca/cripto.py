"""Operações criptográficas: SHA-256 e Ed25519.

Contrato de interoperabilidade (Etapa 1):
  - Hash: SHA-256, 64 caracteres hexadecimais minúsculos.
  - Assinatura: Ed25519 (RFC 8032) aplicada diretamente aos bytes do arquivo, sem pré-hash.
  - Chave pública: PEM SubjectPublicKeyInfo.
  - Chave privada: PEM PKCS#8 (sem senha).
  - Assinatura: arquivo binário com exatamente 64 bytes.
  - Arquivos sempre lidos em modo binário, sem alteração de conteúdo.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TAMANHO_ASSINATURA = 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_BLOCO = 1024 * 1024


class ErroSeguranca(Exception):
    """Erro de uso, arquivo ou formato, com mensagem para o usuário."""


# ---------------------------------------------------------------- arquivos

def ler_bytes(caminho: str | Path) -> bytes:
    p = Path(caminho)
    if not p.exists():
        raise ErroSeguranca(f"arquivo não encontrado: {caminho}")
    if p.is_dir():
        raise ErroSeguranca(f"o caminho é um diretório, não um arquivo: {caminho}")
    try:
        return p.read_bytes()
    except PermissionError:
        raise ErroSeguranca(f"sem permissão para ler: {caminho}") from None
    except OSError as e:
        raise ErroSeguranca(f"não foi possível ler {caminho}: {e.strerror}") from None


def _gravar(caminho: str | Path, dados: bytes, privado: bool = False) -> None:
    p = Path(caminho)
    if p.is_dir():
        raise ErroSeguranca(f"o caminho é um diretório: {caminho}")
    if p.parent and not p.parent.exists():
        raise ErroSeguranca(f"diretório de destino não existe: {p.parent}")
    try:
        if privado:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(dados)
        else:
            p.write_bytes(dados)
    except PermissionError:
        raise ErroSeguranca(f"sem permissão para gravar: {caminho}") from None
    except OSError as e:
        raise ErroSeguranca(f"não foi possível gravar {caminho}: {e.strerror}") from None


# ---------------------------------------------------------------- hash

def sha256_arquivo(caminho: str | Path) -> str:
    """SHA-256 do conteúdo binário do arquivo, em hex minúsculo."""
    p = Path(caminho)
    if not p.exists():
        raise ErroSeguranca(f"arquivo não encontrado: {caminho}")
    if p.is_dir():
        raise ErroSeguranca(f"o caminho é um diretório, não um arquivo: {caminho}")
    h = hashlib.sha256()
    try:
        with p.open("rb") as f:
            for bloco in iter(lambda: f.read(_BLOCO), b""):
                h.update(bloco)
    except OSError as e:
        raise ErroSeguranca(f"não foi possível ler {caminho}: {e.strerror}") from None
    return h.hexdigest()


def normalizar_hash(referencia: str) -> str:
    ref = referencia.strip().lower()
    if not _HEX64.match(ref):
        raise ErroSeguranca(
            "hash de referência inválido: esperado SHA-256 com 64 caracteres hexadecimais"
        )
    return ref


def hash_confere(caminho: str | Path, referencia: str) -> tuple[bool, str, str]:
    ref = normalizar_hash(referencia)
    calculado = sha256_arquivo(caminho)
    return hmac.compare_digest(calculado, ref), calculado, ref


# ---------------------------------------------------------------- chaves

def gerar_par_chaves(caminho_privada: str | Path, caminho_publica: str | Path,
                     sobrescrever: bool = False) -> None:
    if Path(caminho_privada).resolve() == Path(caminho_publica).resolve():
        raise ErroSeguranca("as chaves privada e pública precisam de arquivos diferentes")
    if not sobrescrever:
        for c in (caminho_privada, caminho_publica):
            if Path(c).exists():
                raise ErroSeguranca(f"o arquivo já existe: {c} (use --force para sobrescrever)")
    privada = Ed25519PrivateKey.generate()
    pem_privada = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_publica = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _gravar(caminho_privada, pem_privada, privado=True)
    _gravar(caminho_publica, pem_publica)


def carregar_privada(caminho: str | Path) -> Ed25519PrivateKey:
    dados = ler_bytes(caminho)
    try:
        chave = serialization.load_pem_private_key(dados, password=None)
    except TypeError:
        raise ErroSeguranca(f"chave privada protegida por senha não é suportada: {caminho}") from None
    except (ValueError, UnsupportedAlgorithm):
        if b"PUBLIC KEY" in dados:
            raise ErroSeguranca(f"foi informada uma chave PÚBLICA no lugar da privada: {caminho}") from None
        raise ErroSeguranca(f"chave privada inválida (esperado PEM PKCS#8): {caminho}") from None
    if not isinstance(chave, Ed25519PrivateKey):
        raise ErroSeguranca(f"chave incompatível: a chave privada não é Ed25519: {caminho}")
    return chave


def carregar_publica(caminho: str | Path) -> Ed25519PublicKey:
    dados = ler_bytes(caminho)
    try:
        chave = serialization.load_pem_public_key(dados)
    except (ValueError, UnsupportedAlgorithm):
        if b"PRIVATE KEY" in dados:
            raise ErroSeguranca(f"foi informada uma chave PRIVADA no lugar da pública: {caminho}") from None
        raise ErroSeguranca(f"chave pública inválida (esperado PEM SubjectPublicKeyInfo): {caminho}") from None
    if not isinstance(chave, Ed25519PublicKey):
        raise ErroSeguranca(f"chave incompatível: a chave pública não é Ed25519: {caminho}")
    return chave


# ---------------------------------------------------------------- assinatura

def assinar(caminho_arquivo: str | Path, caminho_privada: str | Path,
            caminho_assinatura: str | Path) -> bytes:
    chave = carregar_privada(caminho_privada)
    mensagem = ler_bytes(caminho_arquivo)
    assinatura = chave.sign(mensagem)  # Ed25519 puro: sem pré-hash
    if len(assinatura) != TAMANHO_ASSINATURA:  # defesa; a biblioteca garante 64
        raise ErroSeguranca("assinatura gerada com tamanho inesperado")
    _gravar(caminho_assinatura, assinatura)
    return assinatura


def verificar(caminho_arquivo: str | Path, caminho_publica: str | Path,
              caminho_assinatura: str | Path) -> tuple[bool, str]:
    """Retorna (válida, motivo). Erros de arquivo/chave levantam ErroSeguranca."""
    chave = carregar_publica(caminho_publica)
    assinatura = ler_bytes(caminho_assinatura)
    mensagem = ler_bytes(caminho_arquivo)
    if len(assinatura) != TAMANHO_ASSINATURA:
        return False, (f"o arquivo de assinatura tem {len(assinatura)} bytes; "
                       f"uma assinatura Ed25519 tem exatamente {TAMANHO_ASSINATURA}")
    try:
        chave.verify(assinatura, mensagem)
    except InvalidSignature:
        return False, ("a assinatura não corresponde a este arquivo e a esta chave pública "
                       "(arquivo alterado, chave errada ou assinatura corrompida)")
    return True, "a assinatura confere com o arquivo e a chave pública"
