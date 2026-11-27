"""Testes automatizados da Etapa 1 (TI01–TI06) e de tratamento de erros.

Executam a CLI exatamente como um usuário faria (python seguranca.py ...),
conferindo saída e código de saída. Todos os arquivos são fictícios e criados
em diretório temporário.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RAIZ = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(RAIZ / "seguranca.py")]

# Vetores de teste conhecidos (NIST FIPS 180-2 / valor do arquivo vazio)
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
SHA256_VAZIO = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def rodar(*args: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run([*CLI, *map(str, args)], capture_output=True, text=True)


def altera_um_byte(origem: Path, destino: Path) -> None:
    dados = bytearray(origem.read_bytes())
    dados[0] ^= 0x01
    destino.write_bytes(bytes(dados))


@pytest.fixture
def doc(tmp_path: Path) -> Path:
    p = tmp_path / "certificado_ficticio.txt"
    p.write_bytes("Certificado fictício de conclusão — Aluno Exemplo da Silva.\r\nCarga horária: 60h\n".encode())
    return p


@pytest.fixture
def chaves(tmp_path: Path) -> tuple[Path, Path]:
    priv, pub = tmp_path / "chave_privada.pem", tmp_path / "chave_publica.pem"
    r = rodar("keygen", priv, pub)
    assert r.returncode == 0, r.stderr
    return priv, pub


# ------------------------------------------------------------------ TI01
@pytest.mark.parametrize("conteudo,esperado", [(b"abc", SHA256_ABC), (b"", SHA256_VAZIO)])
def test_TI01_hash_vetores_conhecidos(tmp_path, conteudo, esperado):
    f = tmp_path / "arquivo.bin"
    f.write_bytes(conteudo)
    r = rodar("hash", f)
    assert r.returncode == 0
    assert r.stdout.strip() == esperado


def test_TI01_hash_arquivo_binario_igual_hashlib(tmp_path):
    f = tmp_path / "binario.bin"
    f.write_bytes(bytes(range(256)) * 8192)  # 2 MiB, maior que o bloco de leitura
    r = rodar("hash", f)
    assert r.returncode == 0
    saida = r.stdout.strip()
    assert saida == hashlib.sha256(f.read_bytes()).hexdigest()
    assert len(saida) == 64 and saida == saida.lower()


# ------------------------------------------------------------------ TI02
def test_TI02_check_detecta_modificacao(tmp_path, doc):
    original = rodar("hash", doc).stdout.strip()

    r_ok = rodar("check", doc, original)
    assert r_ok.returncode == 0 and "OK" in r_ok.stdout

    modificado = tmp_path / "modificado.txt"
    altera_um_byte(doc, modificado)
    r = rodar("check", modificado, original)
    assert r.returncode == 1
    assert "DIVERGENTE" in r.stdout


def test_TI02_check_aceita_referencia_maiuscula(doc):
    original = rodar("hash", doc).stdout.strip()
    assert rodar("check", doc, original.upper()).returncode == 0


# ------------------------------------------------------------------ TI03
def test_TI03_keygen_gera_pem_validos(chaves):
    priv, pub = chaves
    dados_priv, dados_pub = priv.read_bytes(), pub.read_bytes()
    assert dados_priv.startswith(b"-----BEGIN PRIVATE KEY-----")      # PKCS#8
    assert dados_pub.startswith(b"-----BEGIN PUBLIC KEY-----")        # SubjectPublicKeyInfo
    k_priv = serialization.load_pem_private_key(dados_priv, password=None)
    k_pub = serialization.load_pem_public_key(dados_pub)
    assert isinstance(k_priv, Ed25519PrivateKey)
    assert isinstance(k_pub, Ed25519PublicKey)
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    assert k_priv.public_key().public_bytes(*raw) == k_pub.public_bytes(*raw)


def test_TI03_keygen_nao_sobrescreve_sem_force(chaves):
    priv, pub = chaves
    antes = priv.read_bytes()
    r = rodar("keygen", priv, pub)
    assert r.returncode == 2 and "já existe" in r.stderr
    assert priv.read_bytes() == antes
    assert rodar("keygen", priv, pub, "--force").returncode == 0


# ------------------------------------------------------------------ TI04
def test_TI04_assinar_e_verificar_original(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    assert rodar("sign", doc, priv, sig).returncode == 0
    assert sig.stat().st_size == 64

    r = rodar("verify", doc, pub, sig)
    assert r.returncode == 0
    assert "ASSINATURA VÁLIDA" in r.stdout

    # Ed25519 puro sobre os bytes originais: a biblioteca confirma de forma independente
    k_pub = serialization.load_pem_public_key(pub.read_bytes())
    k_pub.verify(sig.read_bytes(), doc.read_bytes())


# ------------------------------------------------------------------ TI05
def test_TI05_arquivo_alterado_invalida_assinatura(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    rodar("sign", doc, priv, sig)
    alterado = tmp_path / "alterado.txt"
    altera_um_byte(doc, alterado)

    r = rodar("verify", alterado, pub, sig)
    assert r.returncode == 1
    assert "ASSINATURA INVÁLIDA" in r.stdout
    assert "ASSINATURA VÁLIDA" not in r.stdout


def test_TI05_assinatura_corrompida_e_invalida(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    rodar("sign", doc, priv, sig)
    corrompida = tmp_path / "corrompida.sig"
    altera_um_byte(sig, corrompida)
    assert rodar("verify", doc, pub, corrompida).returncode == 1

    truncada = tmp_path / "truncada.sig"
    truncada.write_bytes(sig.read_bytes()[:63])
    r = rodar("verify", doc, pub, truncada)
    assert r.returncode == 1 and "63 bytes" in r.stdout


# ------------------------------------------------------------------ TI06
def test_TI06_outra_chave_publica_rejeita(tmp_path, doc, chaves):
    priv, _ = chaves
    sig = tmp_path / "assinatura.sig"
    rodar("sign", doc, priv, sig)
    priv2, pub2 = tmp_path / "outra_privada.pem", tmp_path / "outra_publica.pem"
    assert rodar("keygen", priv2, pub2).returncode == 0

    r = rodar("verify", doc, pub2, sig)
    assert r.returncode == 1
    assert "ASSINATURA INVÁLIDA" in r.stdout


# ------------------------------------------------------- interoperabilidade
@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL não instalado")
def test_interop_openssl_verifica_assinatura_da_ferramenta(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "assinatura.sig"
    rodar("sign", doc, priv, sig)
    r = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
         "-rawin", "-in", str(doc), "-sigfile", str(sig)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL não instalado")
def test_interop_ferramenta_verifica_assinatura_do_openssl(tmp_path, doc):
    priv, pub, sig = tmp_path / "o_priv.pem", tmp_path / "o_pub.pem", tmp_path / "o.sig"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv)], check=True)
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(priv), "-rawin",
                    "-in", str(doc), "-out", str(sig)], check=True)
    r = rodar("verify", doc, pub, sig)
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------- tratamento de erros
def test_erro_arquivo_inexistente(tmp_path):
    for args in (("hash", tmp_path / "nao_existe.txt"),
                 ("check", tmp_path / "nao_existe.txt", SHA256_ABC)):
        r = rodar(*args)
        assert r.returncode == 2 and "não encontrado" in r.stderr
        assert "Traceback" not in r.stderr


def test_erro_caminho_e_diretorio(tmp_path):
    r = rodar("hash", tmp_path)
    assert r.returncode == 2 and "diretório" in r.stderr


def test_erro_destino_inexistente(tmp_path, doc, chaves):
    priv, _ = chaves
    r = rodar("sign", doc, priv, tmp_path / "pasta_inexistente" / "a.sig")
    assert r.returncode == 2 and "não existe" in r.stderr


def test_erro_hash_referencia_mal_formado(doc):
    r = rodar("check", doc, "123abc")
    assert r.returncode == 2 and "64 caracteres" in r.stderr


def test_erro_chaves_trocadas(tmp_path, doc, chaves):
    priv, pub = chaves
    sig = tmp_path / "a.sig"
    r = rodar("sign", doc, pub, sig)
    assert r.returncode == 2 and "PÚBLICA no lugar da privada" in r.stderr
    rodar("sign", doc, priv, sig)
    r = rodar("verify", doc, priv, sig)
    assert r.returncode == 2 and "PRIVADA no lugar da pública" in r.stderr


def test_erro_chave_incompativel_rsa(tmp_path, doc):
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p = tmp_path / "rsa_privada.pem"
    p.write_bytes(rsa_priv.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    r = rodar("sign", doc, p, tmp_path / "a.sig")
    assert r.returncode == 2 and "não é Ed25519" in r.stderr


def test_erro_arquivo_que_nao_e_chave(tmp_path, doc):
    r = rodar("verify", doc, doc, doc)
    assert r.returncode == 2 and "chave pública inválida" in r.stderr


def test_uso_incorreto_retorna_diferente_de_zero():
    assert rodar("verify", "so_um_argumento").returncode != 0
    assert rodar().returncode != 0
