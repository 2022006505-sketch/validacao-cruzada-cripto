"""Operações criptográficas da Etapa 1.

Contrato de interoperabilidade:
  - Hash: SHA-256, 64 caracteres hexadecimais minúsculos (hashlib).
  - Assinatura: Ed25519 (RFC 8032) aplicada diretamente aos bytes do arquivo, sem pré-hash.
  - Chave pública: PEM SubjectPublicKeyInfo. Chave privada: PEM PKCS#8 (sem senha).
  - Assinatura: arquivo binário com exatamente 64 bytes.
  - Arquivos sempre lidos em modo binário, sem alteração de conteúdo.
"""
import hashlib
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ErroSeguranca(Exception):
    """Erro de uso, de arquivo ou de chave, com mensagem para o usuário."""


def ler_bytes(caminho):
    p = Path(caminho)
    if not p.exists():
        raise ErroSeguranca(f"arquivo não encontrado: {caminho}")
    if p.is_dir():
        raise ErroSeguranca(f"o caminho é um diretório, não um arquivo: {caminho}")
    return p.read_bytes()


# ------------------------------------------------------------------ hash (R02, R03)

def sha256_arquivo(caminho):
    """SHA-256 do conteúdo binário do arquivo, em 64 hexadecimais minúsculos."""
    return hashlib.sha256(ler_bytes(caminho)).hexdigest()


def hash_confere(caminho, referencia):
    ref = referencia.strip().lower()
    if not _HEX64.match(ref):
        raise ErroSeguranca("hash de referência inválido: esperado 64 caracteres hexadecimais")
    calculado = sha256_arquivo(caminho)
    return calculado == ref, calculado, ref


# ------------------------------------------------------------------ chaves (R01)

def gerar_par_chaves(caminho_privada, caminho_publica):
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
    Path(caminho_privada).write_bytes(pem_privada)
    Path(caminho_publica).write_bytes(pem_publica)


def carregar_privada(caminho):
    dados = ler_bytes(caminho)
    try:
        chave = serialization.load_pem_private_key(dados, password=None)
    except Exception:
        raise ErroSeguranca(f"chave privada inválida (esperado PEM PKCS#8): {caminho}") from None
    if not isinstance(chave, Ed25519PrivateKey):
        raise ErroSeguranca(f"chave incompatível: não é uma chave privada Ed25519: {caminho}")
    return chave


def carregar_publica(caminho):
    dados = ler_bytes(caminho)
    try:
        chave = serialization.load_pem_public_key(dados)
    except Exception:
        raise ErroSeguranca(f"chave pública inválida (esperado PEM SubjectPublicKeyInfo): {caminho}") from None
    if not isinstance(chave, Ed25519PublicKey):
        raise ErroSeguranca(f"chave incompatível: não é uma chave pública Ed25519: {caminho}")
    return chave


# ------------------------------------------------------------------ assinatura (R04, R05, R06)

def assinar(caminho_arquivo, caminho_privada, caminho_assinatura):
    chave = carregar_privada(caminho_privada)
    mensagem = ler_bytes(caminho_arquivo)
    assinatura = chave.sign(mensagem)  # Ed25519 puro: sem pré-hash
    Path(caminho_assinatura).write_bytes(assinatura)  # exatamente 64 bytes


def verificar(caminho_arquivo, caminho_publica, caminho_assinatura):
    """Retorna True só quando a assinatura confere com o arquivo e a chave pública."""
    chave = carregar_publica(caminho_publica)
    assinatura = ler_bytes(caminho_assinatura)
    mensagem = ler_bytes(caminho_arquivo)
    try:
        chave.verify(assinatura, mensagem)
    except InvalidSignature:
        return False
    return True
