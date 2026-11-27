"""Testes automatizados mínimos da Etapa 1 (TI01–TI06).

Executam a CLI exatamente como um usuário faria (python seguranca.py ...),
conferindo a saída e o código de saída. Todos os arquivos são fictícios e
criados em diretório temporário.
"""
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RAIZ = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(RAIZ / "seguranca.py")]

# "abc" -> vetor conhecido do SHA-256 (NIST FIPS 180-2)
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def rodar(*args):
    return subprocess.run([*CLI, *map(str, args)], capture_output=True, text=True)


@pytest.fixture
def doc(tmp_path):
    p = tmp_path / "documento.txt"
    p.write_bytes(b"Declaracao ficticia de conclusao - Aluno Exemplo da Silva.\n")
    return p


@pytest.fixture
def chaves(tmp_path):
    priv, pub = tmp_path / "chave_privada.pem", tmp_path / "chave_publica.pem"
    assert rodar("keygen", priv, pub).returncode == 0
    return priv, pub


# TI01 — calcular o SHA-256 de um arquivo: hash correto
def test_TI01_hash_correto(tmp_path):
    f = tmp_path / "abc.txt"
    f.write_bytes(b"abc")
    r = rodar("hash", f)
    assert r.returncode == 0
    assert r.stdout.strip() == SHA256_ABC


# TI02 — modificar o arquivo e comparar com o hash original: divergência
def test_TI02_modificacao_detectada(tmp_path, doc):
    original = rodar("hash", doc).stdout.strip()
    modificado = tmp_path / "modificado.txt"
    modificado.write_bytes(doc.read_bytes() + b"X")
    r = rodar("check", modificado, original)
    assert r.returncode == 1
    assert "DIVERGENTE" in r.stdout


# TI03 — gerar um par de chaves: arquivos PEM válidos
def test_TI03_keygen_pem_validos(chaves):
    priv, pub = chaves
    assert priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")  # PKCS#8
    assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")     # SubjectPublicKeyInfo
    k_priv = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    k_pub = serialization.load_pem_public_key(pub.read_bytes())
    assert isinstance(k_priv, Ed25519PrivateKey)
    assert isinstance(k_pub, Ed25519PublicKey)


# TI04 — assinar e verificar o arquivo original: assinatura válida
def test_TI04_assinar_e_verificar(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    assert rodar("sign", doc, priv, sig).returncode == 0
    assert sig.stat().st_size == 64
    r = rodar("verify", doc, pub, sig)
    assert r.returncode == 0
    assert "ASSINATURA VÁLIDA" in r.stdout


# TI05 — alterar o arquivo após a assinatura: assinatura inválida
def test_TI05_arquivo_alterado_invalida(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    rodar("sign", doc, priv, sig)
    alterado = tmp_path / "alterado.txt"
    alterado.write_bytes(doc.read_bytes() + b"X")
    r = rodar("verify", alterado, pub, sig)
    assert r.returncode == 1
    assert "ASSINATURA INVÁLIDA" in r.stdout


# TI06 — verificar utilizando outra chave pública: assinatura inválida
def test_TI06_outra_chave_rejeita(tmp_path, doc, chaves):
    priv, _ = chaves
    sig = tmp_path / "assinatura.sig"
    rodar("sign", doc, priv, sig)
    outra_priv, outra_pub = tmp_path / "outra_priv.pem", tmp_path / "outra_pub.pem"
    assert rodar("keygen", outra_priv, outra_pub).returncode == 0
    r = rodar("verify", doc, outra_pub, sig)
    assert r.returncode == 1
    assert "ASSINATURA INVÁLIDA" in r.stdout
