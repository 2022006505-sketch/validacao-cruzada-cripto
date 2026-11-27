# Relatório Técnico Simplificado — Etapa 1

## 1. Identificação

| Item | Valor |
|---|---|
| Integrante | Maximus Saulo Guerreiro Ferreira (trabalho individual) |
| Disciplina | Segurança da Informação — IFAM |
| Turma | IV |
| Linguagem | Python 3.9 ou superior |
| Repositório | https://github.com/2022006505-sketch/validacao-cruzada-cripto (tag `v1.0-entrega`) |

## 2. Descrição da solução

**Bibliotecas.** As operações de Ed25519 usam o pacote [`cryptography`](https://cryptography.io)
(PyCA), mantido ativamente. O SHA-256 vem do `hashlib`, da biblioteca padrão do Python. Nenhum
algoritmo criptográfico foi implementado à mão.

**Organização.** `src/seguranca/cripto.py` concentra a lógica criptográfica e a leitura de
arquivos; `src/seguranca/cli.py` cuida da interface (argumentos, mensagens e códigos de saída);
`seguranca.py` é o ponto de entrada. Assim, os testes exercitam a CLI como um usuário faria.

**Decisões técnicas (contrato de interoperabilidade).**

- Hash impresso em hexadecimal minúsculo, com 64 caracteres.
- Chave privada em PEM PKCS#8 sem senha; chave pública em PEM SubjectPublicKeyInfo.
- Assinatura gravada crua, com 64 bytes, sem Base64 nem cabeçalho.
- Ed25519 aplicado diretamente sobre os bytes do arquivo, sem pré-hash (Ed25519 puro, RFC 8032).
- Arquivos lidos em modo binário, sem conversão de codificação ou de quebra de linha.
- Códigos de saída: `0` sucesso, `1` verificação falhou, `2` erro de uso/arquivo/chave. As chaves
  são validadas antes do uso (tipo e formato), com mensagens compreensíveis.

## 3. Funcionalidades implementadas (R01–R06)

| Req. | Descrição | Como foi atendido |
|---|---|---|
| R01 | Gerar par de chaves Ed25519 | `keygen <priv> <pub>`, em PEM PKCS#8 e SubjectPublicKeyInfo |
| R02 | SHA-256 de qualquer arquivo | `hash <arquivo>`, com leitura binária |
| R03 | Comparar com hash de referência | `check <arquivo> <hash>`: saída 0 se confere, 1 se diverge |
| R04 | Assinar com a chave privada | `sign <arquivo> <priv> <sig>`, gerando 64 bytes |
| R05 | Verificar com a chave pública | `verify <arquivo> <pub> <sig>`, informando válida ou inválida |
| R06 | Rejeitar assinaturas inválidas | Arquivo alterado ou chave errada resultam em inválida (saída 1) |

Erros comuns (arquivo inexistente, caminho inválido, chave incompatível, hash mal formado) são
tratados com mensagem no *stderr* e saída 2, sem *traceback*.

## 4. Testes realizados

Automatizados em `tests/test_seguranca.py`, executados com `python -m pytest`. Todos usam
arquivos fictícios em diretório temporário.

| ID | Teste | Resultado esperado | Resultado |
|---|---|---|---|
| TI01 | Calcular o SHA-256 do vetor "abc" (NIST FIPS 180-2) | Hash correto | Aprovado |
| TI02 | Modificar o arquivo e comparar com o hash original | Divergência (saída 1) | Aprovado |
| TI03 | Gerar um par de chaves | Arquivos PEM válidos (Ed25519) | Aprovado |
| TI04 | Assinar e verificar o arquivo original | Assinatura válida (64 bytes) | Aprovado |
| TI05 | Alterar o arquivo após a assinatura | Assinatura inválida (saída 1) | Aprovado |
| TI06 | Verificar com outra chave pública | Assinatura inválida (saída 1) | Aprovado |

Resultado: **6 de 6 testes aprovados.**

## 5. Análise técnica e conclusão

**Limitações.** A chave privada é gravada sem senha, porque o contrato pede PKCS#8 simples: quem
obtiver o arquivo consegue assinar em nome do titular. Não há vínculo entre a chave pública e uma
identidade (certificado/ICP), nem carimbo de tempo ou revogação.

**1. Por que um hash SHA-256 isolado não comprova a autoria?** O hash é uma função pública, sem
chave. Qualquer pessoa pode alterar o documento e recalcular o hash, que volta a "conferir". Ele
prova integridade em relação a uma referência confiável, mas não diz quem produziu o documento.

**2. Qual a função das chaves pública e privada?** A chave privada, que fica só com o titular,
gera a assinatura; apenas quem a possui consegue produzi-la. A chave pública é divulgada e permite
que qualquer pessoa verifique a assinatura, sem revelar a chave privada.

**3. Por que alterar um documento assinado invalida a assinatura?** A assinatura Ed25519 é
calculada sobre todos os bytes do documento. Mudar um único byte altera completamente o resultado,
e a equação de verificação deixa de fechar. Produzir uma assinatura válida para o novo conteúdo
exigiria a chave privada.

**4. Cuidados para uso em produção.** Guardar a chave privada protegida (senha, HSM ou cofre de
segredos); vincular a chave pública a uma identidade (certificado digital); adicionar carimbo de
tempo e revogação; distribuir a chave pública por canal confiável; e manter as dependências
atualizadas.

**Conclusão.** A ferramenta atende os requisitos R01–R06 e o contrato de interoperabilidade, com
todos os testes mínimos aprovados.
