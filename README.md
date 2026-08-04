[![Security Tests](https://github.com/j0hnWeider/security-testing/actions/workflows/security-tests.yml/badge.svg)](https://github.com/j0hnWeider/security-testing/actions/workflows/security-tests.yml)
[![Allure Report](https://img.shields.io/badge/Allure-Live_Report-orange?style=flat&logo=allure)](https://j0hnweider.github.io/security-testing)

<div align="center">
  <img src="imagem/banner.webp" alt="Security Testing Banner" width="100%" style="max-width: 800px; border-radius: 12px;">
</div>

<div align="center">

# Security Testing
**Portfólio de Automação e Segurança em APIs**

<p align="center">
  <img src="https://img.shields.io/badge/Playwright-45BA63?style=for-the-badge&logo=playwright&logoColor=white"/>
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP_Top_10-000000?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Allure_Report-FF6C37?style=for-the-badge&logo=allure&logoColor=white"/>
  <img src="https://img.shields.io/github/license/j0hnWeider/security-testing?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Em%20Estudo-blue?style=for-the-badge"/>
</p>

</div>

---

## Minha abordagem neste projeto

Este repositório é a materialização da minha forma de pensar quando o assunto é qualidade e segurança de software.

Em vez de construir um projeto fictício do zero, escolhi a [**ServeRest**](https://serverest.dev) — uma API pública que simula um e-commerce real — como meu "campo de batalha". O objetivo não é apenas executar testes, mas **estruturar uma estratégia de defesa** baseada nos padrões reais de mercado (OWASP).

Aqui, eu não apenas valido se a API funciona; eu valido se ela **resiste** a ataques.

---

## Como eu estruturei a tomada de decisão

Um bom teste não se faz apenas com código, mas com uma boa pergunta. Antes de escrever qualquer script, fiz as seguintes perguntas para definir a estratégia:

### 1. Injeção e Sanitização
> *"Se um usuário mal-intencionado enviar comandos de banco de dados ou scripts maliciosos nos campos de busca ou cadastro, a API vai executá-los ou vai bloqueá-los?"*

**Ação tomada:** Criei testes com payloads reais de SQL, NoSQL, XSS e Path Traversal. Modelei cenários como **buscas por produtos contendo injeção** e **cadastros com scripts maliciosos no nome do usuário** para validar a sanitização real da aplicação.

### 2. Autenticação e Controle de Acesso
> *"O sistema realmente sabe quem é o usuário? Um usuário comum consegue forçar acesso a rotas de administrador ou a dados de outro usuário apenas mudando o ID na requisição?"*

**Ação tomada:** Além de testar tokens malformados e ausência de autenticação, implementei uma suíte completa de **IDOR** (Insecure Direct Object References) para verificar se um usuário comum consegue acessar, editar ou deletar recursos que pertencem a outros. Complementei com testes de **Mass Assignment** para validar se a API filtra campos sensíveis como `administrador: true` enviados por um usuário sem privilégios.

### 3. Configuração do Servidor
> *"O servidor está configurado para evitar ataques simples de engenharia social e vazamento de informações? As políticas de cache, CORS e limites de requisição estão bem ajustadas?"*

**Ação tomada:** Testei headers OWASP em múltiplos endpoints, validei CORS, Cache-Control e implementei **rate limiting sequencial** para simular um ataque real (não apenas rajadas paralelas). Ampliei a cobertura para incluir **timing attack** com análise estatística (50 amostras, mediana e desvio padrão) e **validação de domínios de e-mail suspeitos**.

### 4. Criptografia e Proteção de Dados
> *"As senhas trafegam em texto plano? Os tokens JWT utilizam algoritmos seguros e têm expiração definida? A API impõe políticas mínimas de senha?"*

**Ação tomada:** Desenvolvi testes que decodificam tokens JWT para inspecionar o algoritmo (`alg`) e a presença de `exp`, validam que senhas não vazam nas respostas de criação e consulta, verificam a política de senha (OWASP ASVS recomenda mínimo de 8 caracteres) e confirmam o uso de HTTPS.

### 5. Lógica de Negócio e Concorrência
> *"O que acontece se dois usuários comprarem o último item do estoque exatamente ao mesmo tempo?"*

**Ação tomada:** Criei cenários de **race condition** com `Promise.all` para disparar compras simultâneas e verificar se o estoque fica negativo. Isso vai além de testes de segurança tradicionais e entra em qualidade de negócio — algo que impacta diretamente o bolso de um e-commerce.

---

## O que a execução dos meus testes revelou

Na última execução, a suíte rodou **39 cenários** distribuídos em oito categorias e evidenciou falhas críticas:

### Autenticação e Autorização (8 testes)
- **Falha de Rate Limiting em Login:** API não bloqueia múltiplas tentativas.
- **Domínios Suspeitos Permitidos:** Cadastro com e-mails temporários (mailinator, temp-mail, etc.).

### IDOR (6 testes)
- **Usuário comum lista todos os usuários:** Vazamento de emails e nomes.
- **Acesso a carrinhos alheios:** Comum visualiza carrinhos que não são dele.

### Mass Assignment (5 testes)
- **API aceita tipos errados:** `preco: "gratis"` (string) em vez de número.
- **Campos desconhecidos ignorados silenciosamente:** API não rejeita payload com `campo_inexistente`.

### Criptografia (6 testes)
- **Senha exposta na consulta GET:** API retorna o campo `password` em texto plano.
- **Política de senha fraca:** Aceita senhas de 1 caractere.
- **JWT com HS256:** Algoritmo simétrico — documentado como observação.

### Headers de Segurança (3 testes)
- **CORS Permissivo:** `Access-Control-Allow-Origin: *`.
- **Cache sem `no-store`:** Dados sensíveis podem ser cacheados.

### Injeção (4 testes)
- **XSS Armazenado:** Múltiplos payloads refletidos sem sanitização.
- **NoSQL Injection:** Payloads com operadores `$ne`, `$gt`, `$regex` processados.

### Componentes Desatualizados (4 testes)
- **Header Server exposto:** `Google Frontend`.
- **Headers de segurança ausentes:** CSP, Referrer-Policy, Permissions-Policy.

### Rate Limiting (3 testes)
- **Ausência total de rate limiting:** Nenhum endpoint bloqueia requisições repetidas.

### Race Condition (2 testes)
- **Resultado pendente de execução:** Testes implementados, aguardando confirmação da ServeRest.

---

## Relatório Allure ao vivo

O relatório completo do Allure é publicado automaticamente no GitHub Pages após cada push na branch `main`:

**[https://j0hnweider.github.io/security-testing](https://j0hnweider.github.io/security-testing)**

Lá você encontra:
- Descrições dos testes com alertas concatenados (visíveis sem abrir anexos)
- Evidências em anexo (JSON com payloads, respostas e recomendações)
- Severidade e tags por categoria OWASP
- Histórico de execuções (Trend)
- Classificação por categorias de falha

---

## Sobre a implementação técnica

Este projeto foi construído inteiramente com Playwright e TypeScript, com foco em boas práticas de engenharia de software:
- Criação de dados sob demanda (timestamp + random) para garantir isolamento em pipelines paralelas.
- Tratamento robusto de erros com retries para APIs instáveis (503).
- Alertas concatenados diretamente na descrição principal do Allure, visíveis sem abrir anexos.
- Anexos JSON detalhados mantidos para diagnóstico completo.
- Cliente HTTP centralizado (`ApiClient`) com gerenciamento automático de tokens.
- Execução serial por categoria (`test.describe.serial`) para compartilhar autenticação.

---

## Como reproduzir os testes e gerar as evidências localmente

```bash
# Instalar dependências
npm install
npx playwright install chromium

# Executar a suíte completa com cobertura
npm run test:coverage

# Abrir o relatório Playwright
npx playwright show-report reports/playwright-report

# Gerar e abrir o relatório Allure local
npm run report:allure
```

Relatórios gerados:

- `playwright-report/index.html`: Relatório interativo do Playwright.

- `allure-report/index.html`: Métricas e evidências do Allure.

- `reports/zap-report.html`: Scan do OWASP ZAP via Docker.

---

## Estrutura de código

```
text
security-testing/
├── .github/
│   └── workflows/
│       └── security-tests.yml        # Pipeline CI/CD com deploy no Pages
├── config/
│   └── allure/
│       └── categories.json           # Categorias personalizadas do Allure
├── src/
│   ├── client/
│   │   └── ApiClient.ts              # Cliente HTTP com gerenciamento de tokens
│   ├── fixtures/
│   │   └── auth.fixture.ts           # Fixtures para admin e usuário comum
│   ├── tests/
│   │   └── security/
│   │       ├── auth.spec.ts              # RBAC, brute force, token, timing attack
│   │       ├── crypto.spec.ts            # Senha, JWT, política de senha, HTTPS
│   │       ├── headers.spec.ts           # Headers OWASP, CORS, Cache-Control
│   │       ├── idor.spec.ts              # IDOR: acesso indevido a recursos
│   │       ├── injection.spec.ts         # SQLi, XSS, Path Traversal, NoSQLi
│   │       ├── mass-assignment.spec.ts   # Auto-promoção, ID customizado, tipos
│   │       ├── outdated-components.spec.ts # Server header, stack trace, fingerprinting
│   │       ├── race-condition.spec.ts    # Concorrência em compras
│   │       └── rate-limiting.spec.ts     # Rate limit sequencial e paralelo
│   └── utils/
│       └── allure-helper.ts          # Metadados e anexos do Allure
├── playwright.config.ts
├── package.json
└── README.md
```

---

## Mapeamento OWASP Top 10 (2021)

| Categoria OWASP | Testes | Cenários |
|-----------------|--------|----------|
| A01:2021 - Broken Access Control | SEC-AUTH-02/06, SEC-IDOR-01 a 06, SEC-MASS-01 a 05 | RBAC, Escalação Horizontal, IDOR, Mass Assignment |
| A02:2021 - Cryptographic Failures | SEC-CRYPTO-01 a 06 | Senha exposta, JWT, Política de senha, HTTPS |
| A03:2021 - Injection | CT-SEC-01/02/03/10 | SQLi, XSS, Path Traversal, NoSQLi |
| A04:2021 - Insecure Design | SEC-RATE-01 a 03, SEC-RACE-01/02 | Rate Limiting, Race Condition |
| A05:2021 - Security Misconfiguration | SEC-HEADERS-01 a 03 | Headers HTTP, CORS, Cache |
| A06:2021 - Vulnerable and Outdated Components | SEC-OUTDATED-01 a 04 | Server header, Stack trace, Fingerprinting |
| A07:2021 - Identification and Authentication Failures | SEC-AUTH-01/03/04/05/07 | Brute Force, Token, Enumeração, Timing Attack |
| Engenharia Social | SEC-AUTH-08 | Domínios de e-mail suspeitos |

---

## Principais comandos

```bash
npm run test:security    # Todos os 39 cenários
npm run test:auth        # RBAC, tokens, timing attack
npm run test:crypto      # Senha, JWT, política de senha, HTTPS
npm run test:headers     # CORS e Headers OWASP
npm run test:idor        # Acesso indevido a recursos
npm run test:injection   # SQLi, XSS, NoSQLi, Path Traversal
npm run test:mass        # Auto-promoção, ID customizado, tipos
npm run test:outdated    # Server header, stack trace, fingerprinting
npm run test:race        # Concorrência em compras
npm run test:rate-limit  # Proteção contra força bruta e DoS
npm run coverage         # Cobertura de código
npm run test:zap         # Scan OWASP ZAP via Docker
```

---

## Minha visão sobre próximos passos

Este projeto é vivo e evolui como um laboratório contínuo de segurança ofensiva aplicada a QA. Por se tratar de uma API pública que não está sob meu controle, o foco está em:

### Expansão da cobertura
- **A08:2021 - Software and Data Integrity Failures:** validação de integridade de payloads, desserialização insegura e proteção contra mass assignment avançado.
- **Testes de Boundary/Edge Cases:** payloads de 1MB+, 10.000 caracteres, Unicode, Content-Type alternativos.

### Comparação entre APIs
Aplicar esta mesma suíte contra outras APIs públicas (ReqRes, JSONPlaceholder, GoRest) gerando relatórios comparativos de maturidade de segurança.

### Benchmark de segurança
Scorecard por API testada com métricas como taxa de headers OWASP, vetores de injeção bloqueados vs. refletidos e nota geral de aderência ao OWASP Top 10.

---

MIT License - John Weider
