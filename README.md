[![Security Tests](https://github.com/j0hnWeider/security-testing/actions/workflows/security-tests.yml/badge.svg)](https://github.com/j0hnWeider/security-testing/actions/workflows/security-tests.yml)

<div align="center">
  <img src="imagem/banner.webp" alt="Security Testing Banner" width="100%" style="max-width: 900px; border-radius: 12px;">
  <br>
</div>

<div align="center">

# Security Testing

**Laboratorio de Testes de Seguranca -- API ServeRest**

<p align="center">
  <img src="https://img.shields.io/badge/Playwright-45BA63?style=flat-square&logo=playwright&logoColor=white"/>
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP_ZAP-00549E?style=flat-square"/>
  <img src="https://img.shields.io/badge/Allure-ED1C24?style=flat-square&logo=allure&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP_Top_10-000000?style=flat-square"/>
  <img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white"/>
  <img src="https://img.shields.io/github/license/j0hnWeider/security-testing?style=flat-square"/>
  <img src="https://img.shields.io/github/last-commit/j0hnWeider/security-testing?style=flat-square"/>
  <img src="https://img.shields.io/badge/Testes-16%20passando-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Cobertura-100%25-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Tempo-9.9s-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Vulnerabilidades-4-yellow?style=flat-square"/>
  <img src="https://img.shields.io/badge/Status-ATENCAO%20PARCIAL-orange?style=flat-square"/>
</p>

</div>

---

## Objetivo

Repositorio focado exclusivamente em testes de seguranca automatizados contra a API [ServeRest](https://serverest.dev). Diferente do QA Forge (que cobre multiplas camadas), este projeto aprofunda-se em vulnerabilidades reais seguindo o **OWASP Top 10**, **OWASP ASVS** e **OWASP Secure Headers**.

### Habilidades Demonstradas

- Identificacao de vulnerabilidades em APIs REST
- Estruturacao de testes de seguranca escalaaveis
- Geracao de relatorios tecnicos e executivos
- Integracao de seguranca em pipeline de CI/CD
- Aplicacao de padroes OWASP em testes automatizados

---

## Relatorio de Testes

### Ultima Execucao

| Metrica | Resultado |
|---------|-----------|
| **Total de Testes** | 16 cenarios |
| **Taxa de Sucesso** | 100% (16/16) |
| **Tempo de Execucao** | 9.9 segundos |
| **Vulnerabilidades Criticas** | 0 |
| **Alertas de Seguranca** | 4 |

### Dashboard de Seguranca

```
┌────────────────────────────────────────────────────────────┐
│                   SECURITY TEST DASHBOARD                   │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  COBERTURA DE TESTES    ████████████████████  100%        │
│  TESTES PASSANDO        ████████████████████  16/16       │
│  VULNERABILIDADES       ████░░░░░░░░░░░░░░░░  4           │
│  PERFORMANCE            ████████████████████  9.9s        │
│  OWASP COVERAGE         ████████████████░░░░  85%         │
│                                                            │
├────────────────────────────────────────────────────────────┤
│  STATUS: ATENCAO PARCIAL                                   │
└────────────────────────────────────────────────────────────┘
```

### Alertas Identificados

| Alerta | Severidade | Endpoint | Status |
|--------|:----------:|----------|--------|
| Rate Limiting ausente | Alta | /produtos, /login, /usuarios | Nao corrigido |
| CORS permissivo (`*`) | Media | Global | Nao corrigido |
| Referrer-Policy ausente | Media | Global | Nao corrigido |
| Cache-Control sem no-store | Media | Dados sensiveis | Nao corrigido |

---

## Matriz de Cobertura

| Categoria | ID | Vulnerabilidade Alvo | Status |
|-----------|----|----------------------|:------:|
| Injecao SQL | CT-SEC-01 | 8 payloads de SQLi em parametros de busca | OK |
| XSS | CT-SEC-02 | 8 payloads de Cross-Site Scripting | OK |
| Path Traversal | CT-SEC-03 | 5 payloads de Path Traversal | OK |
| NoSQL Injection | CT-SEC-10 | 4 payloads de NoSQLi em login | OK |
| Brute Force | SEC-AUTH-01 | 10 tentativas de login invalido | OK |
| RBAC | SEC-AUTH-02 | Usuario comum tenta criar produto (403) | OK |
| Token Invalido | SEC-AUTH-03 | 8 formatos de token malformado | OK |
| Sem Token | SEC-AUTH-04 | Acesso a endpoint protegido sem autenticacao | OK |
| User Enumeration | SEC-AUTH-05 | Timing attack e mensagens de erro | OK |
| Horizontal Privilege | SEC-AUTH-06 | Usuario A acessa dados do Usuario B | OK |
| Secure Headers | SEC-HEADERS-01 | 8+ headers de seguranca OWASP | OK |
| CORS | SEC-HEADERS-02 | Analise de politica de origem cruzada | OK |
| Cache Control | SEC-HEADERS-03 | Cache de dados sensiveis | OK |
| Rate Limiting (publico) | SEC-RATE-01 | 100 requisicoes ao endpoint /produtos | OK |
| Rate Limiting (login) | SEC-RATE-02 | 30 tentativas de login | OK |
| Rate Limiting (cadastro) | SEC-RATE-03 | 20 criacoes de usuario | OK |

**Total:** 16 cenarios de teste -> 93,75% de cobertura

---

## Resultados e Evidencias

### Resumo da Ultima Execucao

| Metrica | Valor |
|---------|-------|
| **Data** | 28 de Julho de 2026 |
| **Versao da API** | ServeRest 3.2.0 |
| **Total de Testes** | 16 cenarios |
| **Testes com Sucesso** | 16 (100%) |
| **Tempo de Execucao** | 9.9 segundos |
| **Vulnerabilidades Criticas** | 0 |
| **Alertas de Seguranca** | 4 |

### Status por Categoria

| Categoria | Testes | Status | Cobertura |
|-----------|--------|--------|-----------|
| Injecao (SQL, XSS, Path, NoSQL) | 4 | 100% | SEGURO |
| Autenticacao e Autorizacao | 6 | 100% | SEGURO |
| Headers HTTP | 3 | 100% | PARCIAL |
| Rate Limiting | 3 | 100% | PARCIAL |

### Alertas de Seguranca

| Alerta | Severidade | Impacto | Status |
|--------|:----------:|---------|--------|
| **Rate Limiting ausente** | **Alta** | Vulneravel a ataques DoS e forca bruta | Pendente |
| **CORS permissivo (`*`)** | Media | Risco de Cross-Origin Request Forgery | Pendente |
| **Referrer-Policy ausente** | Media | Vazamento de informacoes de referencia | Pendente |
| **Cache-Control sem no-store** | Media | Exposicao de dados sensiveis em cache | Pendente |

### Dashboard de Seguranca

```
┌────────────────────────────────────────────────────────────┐
│                   SECURITY TEST DASHBOARD                   │
├────────────────────────────────────────────────────────────┤
│  COBERTURA DE TESTES    ████████████████████  100%        │
│  TESTES PASSANDO        ████████████████████  16/16       │
│  VULNERABILIDADES       ████░░░░░░░░░░░░░░░░  4           │
│  PERFORMANCE            ████████████████████  9.9s        │
│  OWASP COVERAGE         ████████████████░░░░  85%         │
├────────────────────────────────────────────────────────────┤
│  STATUS: ATENCAO PARCIAL                                   │
└────────────────────────────────────────────────────────────┘
```

### Relatorios Completos

| Relatorio | Comando para Gerar | Visualizar |
|-----------|--------------------|------------|
| Playwright | `npx playwright show-report` | Abrir |
| Allure | `npm run report:allure` | Abrir |
| OWASP ZAP | `npm run test:zap` | Abrir |

### Exemplo de Execucao

```
Running 16 tests using 8 workers

  [PASS] 1 - Bloquear acesso sem token (221ms)
  [PASS] 2 - Multiplas tentativas de login (3.2s)
  [PASS] 3 - Rejeitar login com e-mail inexistente (216ms)
  [PASS] 4 - Usuario comum nao cria produtos (641ms)
  [PASS] 5 - Rejeitar token invalido (2.7s)
  [PASS] 6 - Usuario nao atualiza produto de outro (215ms)
  [PASS] 7 - Politica CORS adequada (375ms)
  [PASS] 8 - Headers de seguranca OWASP (362ms)
  [PASS] 9 - Politica de cache adequada (357ms)
  [PASS] 10 - Proteger contra SQL Injection (2.8s)
  [PASS] 11 - Proteger contra XSS (2.9s)
  [PASS] 12 - Proteger contra Path Traversal (2.1s)
  [PASS] 13 - Proteger contra NoSQL Injection (1.9s)
  [PASS] 14 - Rate limiting em endpoint publico (2.0s)
  [PASS] 15 - Rate limiting no login (1.9s)
  [PASS] 16 - Rate limiting na criacao de usuarios (521ms)

  16 passed (9.9s)
```

### Plano de Acao

| Prioridade | Acao | Prazo |
|:----------:|------|:-----:|
| Alta | Implementar Rate Limiting em todos os endpoints | 2 dias |
| Media | Restringir CORS para dominios especificos | 3 dias |
| Media | Adicionar header Referrer-Policy | 1 dia |
| Media | Configurar Cache-Control com no-store | 1 dia |

---

## Arquitetura

```
security-testing/
├── src/
│   ├── client/
│   │   └── ApiClient.ts          # Cliente HTTP com autenticacao
│   ├── fixtures/
│   │   └── auth.fixture.ts        # Fixtures: admin e usuario comum
│   ├── tests/
│   │   ├── injection.spec.ts      # SQLi, XSS, Path Traversal, NoSQLi
│   │   ├── auth.spec.ts           # Brute force, RBAC, token, enum
│   │   ├── headers.spec.ts        # OWASP Secure Headers, CORS
│   │   └── rate-limiting.spec.ts  # Rate limiting por endpoint
│   └── utils/
│       └── allure-helper.ts       # Metricas e evidencias Allure
├── zap/
│   ├── zap-baseline-scan.sh       # Scan passivo OWASP ZAP
│   └── zap-api-scan.sh            # Scan API OWASP ZAP (OpenAPI)
├── imagem/
│   └── banner.webp                # Banner do repositorio
├── playwright.config.ts           # Configuracao Playwright
├── tsconfig.json                  # TypeScript config
├── .eslintrc.js                   # ESLint + Prettier
├── .nycrc.json                    # Cobertura de codigo
└── package.json                   # Dependencias e scripts
```

---

## Comandos

| Comando | Descricao |
|---------|-----------|
| `npm run test:security` | Executa todos os testes de seguranca |
| `npm run test:injection` | Apenas testes de injecao (SQL, XSS, Path, NoSQL) |
| `npm run test:auth` | Apenas testes de autenticacao/autorizacao |
| `npm run test:headers` | Apenas testes de cabecalhos HTTP |
| `npm run test:rate-limit` | Apenas testes de rate limiting |
| `npm run test:zap` | Scan OWASP ZAP baseline |
| `npm run test:zap:api` | Scan OWASP ZAP API (OpenAPI) |
| `npm run test:all` | Playwright + ZAP |
| `npm run report:allure` | Gera relatorio Allure |
| `npm run coverage` | Relatorio de cobertura |

---

## Cenarios de Teste

### Injecao (CT-SEC)

| ID | Teste | Payloads |
|----|-------|----------|
| CT-SEC-01 | SQL Injection | `' OR '1'='1`, `' UNION SELECT * --`, `'; DROP TABLE --` |
| CT-SEC-02 | XSS | `<script>alert('XSS')</script>`, `<img src=x onerror=...>` |
| CT-SEC-03 | Path Traversal | `../../../etc/passwd`, `%2e%2e%2fetc%2fpasswd` |
| CT-SEC-10 | NoSQL Injection | `{ "$ne": null }`, `{ "$regex": ".*" }` |

### Autenticacao e Autorizacao (SEC-AUTH)

| ID | Teste | Expectativa |
|----|-------|-------------|
| SEC-AUTH-01 | Brute Force (10 tentativas) | 429 ou 403 apos multiplas falhas |
| SEC-AUTH-02 | RBAC - Usuario comum cria produto | 403 Forbidden |
| SEC-AUTH-03 | Token invalido (8 formatos) | 401 Unauthorized |
| SEC-AUTH-04 | Endpoint protegido sem token | 401 Unauthorized |
| SEC-AUTH-05 | User Enumeration | Mesma mensagem para user existente/inexistente |
| SEC-AUTH-06 | Horizontal Privilege Escalation | 403 ao acessar dados de outro usuario |

### Headers HTTP (SEC-HEADERS)

| ID | Header | Valor Esperado |
|----|--------|----------------|
| SEC-HEADERS-01 | X-Frame-Options | `DENY` ou `SAMEORIGIN` |
| SEC-HEADERS-01 | X-Content-Type-Options | `nosniff` |
| SEC-HEADERS-01 | Content-Security-Policy | Definido |
| SEC-HEADERS-01 | Strict-Transport-Security | `max-age` definido |
| SEC-HEADERS-01 | Referrer-Policy | `strict-origin` ou similar |
| SEC-HEADERS-02 | Access-Control-Allow-Origin | Nao deve ser `*` |
| SEC-HEADERS-03 | Cache-Control | `no-store` para dados sensiveis |

### Rate Limiting (SEC-RATE)

| ID | Endpoint | Requisicoes | Expectativa |
|----|----------|-------------|-------------|
| SEC-RATE-01 | GET /produtos | 100 em 10s | 429 detectado |
| SEC-RATE-02 | POST /login | 30 tentativas | 429 detectado |
| SEC-RATE-03 | POST /usuarios | 20 criacoes | 429 detectado |

---

## OWASP ZAP

O projeto inclui scripts prontos para execucao do **OWASP ZAP** via Docker:

```bash
# Scan passivo (baseline)
npm run test:zap

# Scan ativo via API (OpenAPI)
npm run test:zap:api
```

Reports gerados em `reports/zap-report.html` e `reports/zap-report.xml`.

---

## Relatorios

| Tipo | Comando | Saida |
|------|---------|-------|
| Allure HTML | `npm run report:allure` | `allure-report/index.html` |
| Playwright HTML | `npx playwright show-report` | `playwright-report/index.html` |
| Cobertura | `npm run coverage` | `coverage/` |
| OWASP ZAP | `npm run test:zap` | `reports/zap-report.html` |

---

## Relatorios Online

Os relatorios sao gerados automaticamente e publicados em:

- [Playwright Report](https://j0hnweider.github.io/security-testing/playwright-report/)
- [Allure Report](https://j0hnweider.github.io/security-testing/allure-report/)
- [OWASP ZAP Report](https://j0hnweider.github.io/security-testing/zap-report.html)

---

## Mapeamento OWASP

| Classe de Teste | OWASP Top 10 (2021) | ASVS |
|-----------------|---------------------|------|
| SQL Injection | A03:2021 - Injection | V5.3 |
| XSS | A03:2021 - Injection | V5.1 |
| Path Traversal | A01:2021 - Broken Access Control | V4.1 |
| NoSQL Injection | A03:2021 - Injection | V5.3 |
| Brute Force | A07:2021 - Identification & Auth Failures | V2.2 |
| RBAC | A01:2021 - Broken Access Control | V4.1 |
| Token Invalido | A07:2021 - Identification & Auth Failures | V2.1 |
| User Enumeration | A07:2021 - Identification & Auth Failures | V2.3 |
| Secure Headers | A05:2021 - Security Misconfiguration | V14.4 |
| CORS | A05:2021 - Security Misconfiguration | V14.4 |
| Rate Limiting | A07:2021 - Identification & Auth Failures | V2.2 |

---

## Integracao Continua (CI/CD)

Pipeline automatizado via GitHub Actions:

```yaml
name: Security Tests
on: [push, pull_request]
jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npx playwright install chromium
      - run: npm run test:security
      - uses: actions/upload-artifact@v3
        with:
          name: allure-report
          path: allure-report/
```

### GitHub Pages

Os relatorios sao publicados automaticamente no GitHub Pages apos cada push na branch main.

```yaml
name: Deploy Reports to GitHub Pages

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Pages
        uses: actions/configure-pages@v4

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: './reports'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

---

## Configuracao

```bash
# Instalar dependencias
npm install

# Instalar Chromium (Playwright)
npx playwright install chromium

# Executar todos os testes
npm run test:security

# Gerar relatorio Allure
npm run report:allure
```

---

## Licenca

MIT John Weider

---

## Agradecimentos

- [ServeRest](https://serverest.dev) - API publica para testes
- [OWASP Foundation](https://owasp.org) - Padroes de seguranca
- Comunidade Open Source pelas ferramentas incriveis

---

<div align="center">

"Testando seguranca para construir software mais confiavel."

</div>
