#!/usr/bin/env bash
# Demonstração completa da ferramenta com arquivos fictícios.
# Uso (a partir da raiz do repositório): bash exemplos/demo.sh
set -u
cd "$(dirname "$0")/.."
T="$(mktemp -d)"
cp exemplos/declaracao_ficticia.txt "$T/documento.txt"
S="python3 seguranca.py"
passo() { echo; echo "\$ $*"; "$@"; echo "[código de saída: $?]"; }

echo "== R02: hash =="
passo $S hash "$T/documento.txt"
H="$($S hash "$T/documento.txt")"

echo; echo "== R03: check (original e modificado) =="
passo $S check "$T/documento.txt" "$H"
cp "$T/documento.txt" "$T/documento_modificado.txt"; printf 'X' >> "$T/documento_modificado.txt"
passo $S check "$T/documento_modificado.txt" "$H"

echo; echo "== R01: keygen =="
passo $S keygen "$T/chave_privada.pem" "$T/chave_publica.pem"
echo; head -1 "$T/chave_privada.pem"; cat "$T/chave_publica.pem"

echo; echo "== R04/R05: sign + verify =="
passo $S sign "$T/documento.txt" "$T/chave_privada.pem" "$T/assinatura.sig"
echo "tamanho da assinatura: $(wc -c < "$T/assinatura.sig") bytes"
passo $S verify "$T/documento.txt" "$T/chave_publica.pem" "$T/assinatura.sig"

echo; echo "== R06: adulteração e chave errada =="
passo $S verify "$T/documento_modificado.txt" "$T/chave_publica.pem" "$T/assinatura.sig"
$S keygen "$T/outra_privada.pem" "$T/outra_publica.pem" >/dev/null
passo $S verify "$T/documento.txt" "$T/outra_publica.pem" "$T/assinatura.sig"

echo; echo "== Tratamento de erros =="
passo $S hash "$T/nao_existe.txt"
passo $S sign "$T/documento.txt" "$T/chave_publica.pem" "$T/x.sig"
passo $S check "$T/documento.txt" "abc123"

rm -rf "$T"
