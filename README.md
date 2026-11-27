# seguranca: integridade e assinatura digital de arquivos

Ferramenta de linha de comando (CLI) para:

- calcular e comparar hashes **SHA-256**;
- gerar pares de chaves **Ed25519**;
- assinar arquivos e verificar assinaturas digitais.

Trabalho Prático, Etapa 1, de Segurança da Informação (IFAM). O relatório técnico está em
[`docs/RELATORIO_TECNICO.md`](docs/RELATORIO_TECNICO.md).

## Requisitos

- Python **3.9 ou superior** e `pip`.

## Instalação

```bash
git clone https://github.com/2022006505-sketch/validacao-cruzada-cripto.git
cd validacao-cruzada-cripto
git checkout v1.0-entrega            # versão oficial da entrega

python -m venv .venv
.venv\Scripts\activate               # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Execução

Todos os comandos são executados a partir da raiz do repositório. A ordem dos argumentos
segue o contrato do enunciado.

```bash
# Gerar chaves (privada em PEM PKCS#8, pública em PEM SubjectPublicKeyInfo)
python seguranca.py keygen chave_privada.pem chave_publica.pem

# Calcular hash (imprime 64 caracteres hexadecimais minúsculos)
python seguranca.py hash documento.txt

# Comparar hash com uma referência
python seguranca.py check documento.txt HASH_REFERENCIA

# Assinar arquivo (gera um arquivo binário com exatamente 64 bytes)
python seguranca.py sign documento.txt chave_privada.pem assinatura.sig

# Verificar assinatura
python seguranca.py verify documento.txt chave_publica.pem assinatura.sig
```

> No Linux/macOS, use `python3` no lugar de `python`.

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Sucesso: hash confere ou assinatura válida |
| `1` | A verificação falhou: hash divergente ou assinatura inválida |
| `2` | Erro: arquivo inexistente, caminho inválido, chave incompatível ou uso incorreto |

As mensagens de erro saem no *stderr* e os resultados no *stdout*. Uma verificação que falha
nunca é apresentada como válida.

## Exemplo de uso

```bash
python seguranca.py keygen chave_privada.pem chave_publica.pem
python seguranca.py hash exemplos/declaracao_ficticia.txt
python seguranca.py sign exemplos/declaracao_ficticia.txt chave_privada.pem assinatura.sig
python seguranca.py verify exemplos/declaracao_ficticia.txt chave_publica.pem assinatura.sig
# -> RESULTADO: ASSINATURA VÁLIDA
```

## Testes automatizados

```bash
python -m pytest
```

São os 6 testes mínimos exigidos no enunciado (TI01–TI06), que usam arquivos fictícios
criados em diretório temporário.

## Estrutura

```
├── seguranca.py              # ponto de entrada (python seguranca.py ...)
├── src/seguranca/
│   ├── cli.py                # interface de linha de comando e códigos de saída
│   └── cripto.py             # SHA-256, Ed25519 e leitura de arquivos
├── tests/test_seguranca.py   # testes automatizados TI01–TI06 (pytest)
├── exemplos/                 # documento fictício de demonstração
├── docs/RELATORIO_TECNICO.md
└── requirements.txt
```

> Nenhuma chave privada é versionada. Todos os documentos de teste são fictícios.
