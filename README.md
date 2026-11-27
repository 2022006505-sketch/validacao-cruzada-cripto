# seguranca: integridade e assinatura digital de arquivos

Ferramenta de linha de comando para:

- calcular e comparar hashes **SHA-256**;
- gerar pares de chaves **Ed25519**;
- assinar arquivos e verificar assinaturas digitais.

Trabalho Prático, Etapa 1, de Segurança da Informação (IFAM). O relatório técnico está em
[`docs/RELATORIO_TECNICO.md`](docs/RELATORIO_TECNICO.md).

## Requisitos

- Python **3.9 ou superior**
- `pip`
- OpenSSL: opcional, usado só em dois testes de interoperabilidade, que são pulados se ele não
  estiver instalado

## Instalação

```bash
git clone https://github.com/2022006505-sketch/validacao-cruzada-cripto.git
cd validacao-cruzada-cripto
git checkout v1.0-entrega            # versão oficial da entrega

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Execução

Todos os comandos são executados a partir da raiz do repositório:

```bash
python3 seguranca.py <comando> [argumentos]
```

No Windows, use `python` no lugar de `python3`. A forma `python3 -m seguranca`, executada de
dentro de `src/`, é equivalente.

## Comandos

A ordem dos argumentos segue o contrato do enunciado.

```bash
# Gerar chaves (privada em PEM PKCS#8, pública em PEM SubjectPublicKeyInfo)
python3 seguranca.py keygen chave_privada.pem chave_publica.pem

# Calcular hash (imprime 64 caracteres hexadecimais minúsculos)
python3 seguranca.py hash documento.txt

# Comparar hash
python3 seguranca.py check documento.txt HASH_REFERENCIA

# Assinar arquivo (gera um arquivo binário com exatamente 64 bytes)
python3 seguranca.py sign documento.txt chave_privada.pem assinatura.sig

# Verificar assinatura
python3 seguranca.py verify documento.txt chave_publica.pem assinatura.sig
```

O `keygen` não sobrescreve arquivos que já existem. Para substituí-los, acrescente `--force`
ao final do comando.

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Sucesso: hash confere ou assinatura válida |
| `1` | A verificação falhou: hash divergente ou assinatura inválida |
| `2` | Erro: arquivo inexistente, caminho inválido, chave incompatível ou uso incorreto |

As mensagens de erro saem no *stderr* e os resultados no *stdout*. Uma verificação que falha
nunca é apresentada como válida.

## Exemplo de uso

```text
$ python3 seguranca.py keygen chave_privada.pem chave_publica.pem
Par de chaves Ed25519 gerado.

$ python3 seguranca.py hash exemplos/declaracao_ficticia.txt
dcc541f73a64336217f2f88fa6ab626d4abf0c4c4644e652a879a91e12ed198a

$ python3 seguranca.py sign exemplos/declaracao_ficticia.txt chave_privada.pem assinatura.sig
Assinatura Ed25519 (64 bytes) gravada em: assinatura.sig

$ python3 seguranca.py verify exemplos/declaracao_ficticia.txt chave_publica.pem assinatura.sig
RESULTADO: ASSINATURA VÁLIDA
```

Para rodar a demonstração completa, com todos os requisitos e casos de erro e usando arquivos
temporários:

```bash
bash exemplos/demo.sh
```

## Testes automatizados

```bash
python3 -m pytest
```

São 21 testes, que cobrem:

- os testes TI01–TI06 exigidos no enunciado;
- o tratamento de erros;
- a interoperabilidade com o OpenSSL, nos dois sentidos.

A saída registrada está em [`docs/evidencias/`](docs/evidencias/).

## Estrutura

```
├── seguranca.py              # ponto de entrada (python3 seguranca.py ...)
├── src/seguranca/
│   ├── cli.py                # interface de linha de comando e códigos de saída
│   └── cripto.py             # SHA-256, Ed25519, leitura/gravação de arquivos e erros
├── tests/test_seguranca.py   # testes automatizados (pytest)
├── exemplos/                 # documento fictício e script de demonstração
├── docs/
│   ├── RELATORIO_TECNICO.md
│   └── evidencias/           # saídas registradas dos testes
├── requirements.txt
└── pyproject.toml            # configuração do pytest
```

> Nenhuma chave privada é versionada. Todos os documentos de teste são fictícios.
