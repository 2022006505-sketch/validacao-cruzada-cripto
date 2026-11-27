"""Interface de linha de comando.

    seguranca keygen chave_privada.pem chave_publica.pem
    seguranca hash documento.txt
    seguranca check documento.txt HASH_REFERENCIA
    seguranca sign documento.txt chave_privada.pem assinatura.sig
    seguranca verify documento.txt chave_publica.pem assinatura.sig

Códigos de saída:
    0  sucesso (hash confere / assinatura válida)
    1  verificação falhou (hash divergente / assinatura inválida)
    2  erro (arquivo inexistente, caminho inválido, chave incompatível, uso incorreto)
"""
import argparse
import sys

from .cripto import (
    ErroSeguranca,
    assinar,
    gerar_par_chaves,
    hash_confere,
    sha256_arquivo,
    verificar,
)

SUCESSO, FALHA, ERRO = 0, 1, 2


def _keygen(a):
    gerar_par_chaves(a.chave_privada, a.chave_publica)
    print("Par de chaves Ed25519 gerado.")
    print(f"  chave privada (PEM PKCS#8): {a.chave_privada}")
    print(f"  chave pública (PEM SubjectPublicKeyInfo): {a.chave_publica}")
    return SUCESSO


def _hash(a):
    print(sha256_arquivo(a.arquivo))
    return SUCESSO


def _check(a):
    ok, calculado, referencia = hash_confere(a.arquivo, a.hash_referencia)
    print(f"Hash calculado:  {calculado}")
    print(f"Hash referência: {referencia}")
    if ok:
        print("RESULTADO: OK — o hash corresponde à referência.")
        return SUCESSO
    print("RESULTADO: DIVERGENTE — o hash NÃO corresponde à referência.")
    return FALHA


def _sign(a):
    assinar(a.arquivo, a.chave_privada, a.assinatura)
    print(f"Assinatura Ed25519 (64 bytes) gravada em: {a.assinatura}")
    return SUCESSO


def _verify(a):
    if verificar(a.arquivo, a.chave_publica, a.assinatura):
        print("RESULTADO: ASSINATURA VÁLIDA")
        return SUCESSO
    print("RESULTADO: ASSINATURA INVÁLIDA")
    return FALHA


def construir_parser():
    p = argparse.ArgumentParser(
        prog="seguranca",
        description="Integridade (SHA-256) e assinatura digital (Ed25519) de arquivos.",
    )
    sub = p.add_subparsers(dest="comando", metavar="COMANDO")
    sub.required = True

    s = sub.add_parser("keygen", help="gera um par de chaves Ed25519 em PEM")
    s.add_argument("chave_privada")
    s.add_argument("chave_publica")
    s.set_defaults(func=_keygen)

    s = sub.add_parser("hash", help="calcula o SHA-256 de um arquivo")
    s.add_argument("arquivo")
    s.set_defaults(func=_hash)

    s = sub.add_parser("check", help="compara o SHA-256 de um arquivo com um hash de referência")
    s.add_argument("arquivo")
    s.add_argument("hash_referencia")
    s.set_defaults(func=_check)

    s = sub.add_parser("sign", help="assina um arquivo com a chave privada")
    s.add_argument("arquivo")
    s.add_argument("chave_privada")
    s.add_argument("assinatura")
    s.set_defaults(func=_sign)

    s = sub.add_parser("verify", help="verifica a assinatura de um arquivo com a chave pública")
    s.add_argument("arquivo")
    s.add_argument("chave_publica")
    s.add_argument("assinatura")
    s.set_defaults(func=_verify)
    return p


def main(argv=None):
    try:
        args = construir_parser().parse_args(argv)
    except SystemExit as e:  # uso incorreto sai com código != 0
        return int(e.code or 0)
    try:
        return args.func(args)
    except ErroSeguranca as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return ERRO


if __name__ == "__main__":
    sys.exit(main())
