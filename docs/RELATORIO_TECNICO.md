# Relatório Técnico Simplificado: Etapa 1

## 1. Identificação

| Item | Valor |
|---|---|
| Integrante | Maximus Saulo Guerreiro Ferreira (trabalho individual) |
| Curso / disciplina | Engenharia de Software, Segurança da Informação, IFAM |
| Linguagem | Python 3.9 ou superior |
| Repositório | https://github.com/2022006505-sketch/validacao-cruzada-cripto (tag `v1.0-entrega`) |

## 2. Descrição da solução

**Biblioteca.** As operações de Ed25519 usam o pacote [`cryptography`](https://cryptography.io)
(PyCA), mantido ativamente e apoiado no OpenSSL. O SHA-256 vem do `hashlib`, da biblioteca padrão
do Python. Nenhum algoritmo foi implementado à mão.

**Organização.**

- `src/seguranca/cripto.py` concentra a lógica criptográfica, a leitura e gravação de arquivos e
  a validação de chaves.
- `src/seguranca/cli.py` cuida apenas da interface (argumentos, mensagens e códigos de saída).
- `seguranca.py` é o ponto de entrada.

Com essa separação, os testes exercitam a CLI exatamente como um usuário faria.

**Principais decisões técnicas.**

- **Contrato de interoperabilidade.**
  - O hash é impresso em hexadecimal minúsculo, com 64 caracteres.
  - A chave privada é gravada em PEM PKCS#8 sem senha, e a pública em PEM SubjectPublicKeyInfo.
  - A assinatura é gravada crua, com 64 bytes, sem Base64 nem cabeçalho.
  - O Ed25519 é aplicado diretamente sobre os bytes do arquivo, sem pré-hash (Ed25519 puro,
    RFC 8032).
  - Todos os arquivos são lidos em modo binário. Não há conversão de codificação nem de quebra de
    linha.
- **Códigos de saída.** `0` indica sucesso, `1` indica verificação falhou (hash divergente ou
  assinatura inválida) e `2` indica erro de uso, arquivo ou chave. Com isso, um script consegue
  distinguir um documento adulterado de um caminho digitado errado.
- **Comparação de hash em tempo constante**, com `hmac.compare_digest`. A referência informada é
  validada (64 caracteres hexadecimais) e normalizada para minúsculas.
- **Validação de chaves antes do uso.** A ferramenta detecta quatro situações e informa cada uma
  com uma mensagem própria:
  - chave pública passada no lugar da privada, ou o contrário;
  - chave de outro algoritmo, como RSA;
  - arquivo que não é PEM;
  - chave protegida por senha.
- **Proteção da chave privada.** Ela é criada com permissão `0600` em sistemas Unix. O `keygen`
  não sobrescreve arquivos existentes sem a opção `--force`.
- **Hash em blocos de 1 MiB**, para suportar arquivos grandes sem carregá-los inteiros na memória.

## 3. Funcionalidades implementadas

| Req. | Descrição | Como foi atendido |
|---|---|---|
| R01 | Gerar par de chaves Ed25519 | `keygen <priv> <pub>`, com PEM PKCS#8 e SPKI |
| R02 | SHA-256 de qualquer arquivo | `hash <arquivo>`, com leitura binária em blocos |
| R03 | Comparar com hash de referência | `check <arquivo> <hash>`, que retorna 0 se OK e 1 se divergente |
| R04 | Assinar com a chave privada | `sign <arquivo> <priv> <sig>`, que grava 64 bytes |
| R05 | Verificar com a chave pública | `verify <arquivo> <pub> <sig>`, com mensagem explícita de válida ou inválida |
| R06 | Rejeitar assinaturas inválidas | Rejeita arquivo alterado, outra chave e assinatura corrompida ou truncada (saída 1) |
| — | Tratamento de erros | Arquivo inexistente, diretório, destino inexistente, chave trocada ou incompatível, hash mal formado (saída 2, sem *traceback*) |

## 4. Testes realizados

Os testes estão automatizados em `tests/test_seguranca.py` e são executados com
`python3 -m pytest`. Todos usam arquivos fictícios criados em diretório temporário.

| ID | Teste | Resultado esperado | Resultado obtido | Evidência |
|---|---|---|---|---|
| TI01 | SHA-256 dos vetores "abc" (NIST FIPS 180-2) e vazio, e de um binário de 2 MiB comparado ao `hashlib` | Hash correto | Aprovado | `test_TI01_*` |
| TI02 | Alterar 1 byte e rodar `check` contra o hash original | Divergência (saída 1) | Aprovado | `test_TI02_*` |
| TI03 | `keygen`: cabeçalhos PEM, tipo Ed25519 e a pública corresponde à privada | PEM válidos | Aprovado | `test_TI03_*` |
| TI04 | Assinar e verificar o original, mais verificação independente pela biblioteca | Assinatura válida | Aprovado | `test_TI04_*` |
| TI05 | Alterar 1 byte após a assinatura, mais assinatura corrompida e truncada | Assinatura inválida | Aprovado | `test_TI05_*` |
| TI06 | Verificar com a chave pública de outro par | Assinatura inválida | Aprovado | `test_TI06_*` |
| Extra | Interoperabilidade com o OpenSSL nos dois sentidos, e 8 casos de erro | OpenSSL aceita e mensagens claras | Aprovado | `test_interop_*`, `test_erro_*` |

Resultado: **21 de 21 testes aprovados.** A saída completa está em
[`evidencias/testes_automatizados.txt`](evidencias/testes_automatizados.txt), e a execução
manual de todos os comandos, com os códigos de saída, está em
[`evidencias/execucao_demo.txt`](evidencias/execucao_demo.txt).

## 5. Análise técnica e conclusão

**Limitações.**

- A chave privada é gravada sem senha, porque o contrato pede PKCS#8 simples. Qualquer pessoa
  que obtenha esse arquivo consegue assinar em nome do titular.
- Não existe vínculo entre a chave pública e uma identidade (certificado ou ICP). A ferramenta
  prova que o documento foi assinado com *aquela* chave, mas não diz *de quem* ela é.
- A assinatura não tem carimbo de tempo nem mecanismo de revogação.
- O `sign` e o `verify` carregam o arquivo inteiro na memória.

**1. Por que um hash SHA-256 isolado não comprova a autoria?** O hash é uma função pública, sem
chave. Qualquer pessoa pode alterar o documento e calcular o novo hash, que passa a "conferir".
O hash só prova integridade em relação a uma referência confiável. Ele não diz quem produziu o
documento.

**2. Qual a função das chaves pública e privada?** A chave privada, que fica só com o titular,
gera a assinatura, e só quem a possui consegue produzi-la. A chave pública é divulgada e permite
que qualquer pessoa verifique se a assinatura foi gerada pela privada correspondente, sem que
essa privada seja revelada.

**3. Por que alterar um documento assinado invalida a assinatura?** A assinatura Ed25519 é
calculada sobre todos os bytes do documento, que passam internamente pelo SHA-512. Mudar um único
byte muda completamente esse resumo, e a equação de verificação deixa de fechar. Produzir uma
assinatura válida para o novo conteúdo exigiria a chave privada.

**4. Cuidados para uso em produção.**

- Guardar a chave privada protegida: com senha, num HSM ou num cofre de segredos, com controle de
  acesso e rotação.
- Vincular a chave pública a uma identidade, por meio de certificado digital ou ICP-Brasil.
- Adicionar carimbo de tempo e lista de revogação.
- Distribuir a chave pública por canal confiável.
- Registrar trilha de auditoria.
- Manter as dependências atualizadas.
- Usar processamento em fluxo para arquivos muito grandes.

**Conclusão.** A ferramenta atende os requisitos R01–R06 e o contrato de interoperabilidade.
Todos os testes obrigatórios e complementares foram aprovados. O teste com o OpenSSL indica que
os artefatos gerados (PEM e assinatura de 64 bytes) são compatíveis com outras implementações
corretas de Ed25519, que é o que a Etapa 2 vai avaliar.
