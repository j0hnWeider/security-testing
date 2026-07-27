<div align="center">
  <img src="imagem/banner.webp" alt="Security Testing Banner" width="100%" style="max-width: 900px; border-radius: 12px;">
  <br>
</div>

<div align="center">

#  Security Testing

**Laboratório de Testes de Segurança — API ServeRest**

<p align="center">
  <img src="https://img.shields.io/badge/Playwright-45BA63?style=flat-square&logo=playwright&logoColor=white"/>
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP_ZAP-00549E?style=flat-square"/>
  <img src="https://img.shields.io/badge/Allure-ED1C24?style=flat-square&logo=allure&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP_Top_10-000000?style=flat-square"/>
  <img src="https://img.shields.io/github/license/j0hnWeider/security-testing?style=flat-square"/>
</p>

</div>

---

##  Objetivo

Repositório focado exclusivamente em **testes de segurança** contra a API [ServeRest](https://serverest.dev). Diferente do QA Forge (que cobre múltiplas camadas), este projeto aprofunda-se em vulnerabilidades reais seguindo o **OWASP Top 10**, **OWASP ASVS** e **OWASP Secure Headers**.

---

##  Matriz de Cobertura

| Categoria | ID | Vulnerabilidade Alvo | Status |
|-----------|----|----------------------|:------:|
| **Injeção SQL** | CT-SEC-01 | 8 payloads de SQLi em parâmetros de busca | ✅ |
| **XSS** | CT-SEC-02 | 8 payloads de Cross-Site Scripting | ✅ |
| **Path Traversal** | CT-SEC-03 | 5 payloads de Path Traversal | ✅ |
| **NoSQL Injection** | CT-SEC-10 | 4 payloads de NoSQLi em login | ✅ |
| **Brute Force** | SEC-AUTH-01 | 10 tentativas de login inválido | ✅ |
| **RBAC** | SEC-AUTH-02 | Usuário comum tenta criar produto (403) | ✅ |
| **Token Inválido** | SEC-AUTH-03 | 8 formatos de token malformado | ✅ |
| **Sem Token** | SEC-AUTH-04 | Acesso a endpoint protegido sem autenticação | ✅ |
| **User Enumeration** | SEC-AUTH-05 | Timing attack e mensagens de erro | ✅ |
| **Horizontal Privilege** | SEC-AUTH-06 | Usuário A acessa dados do Usuário B | ✅ |
| **Secure Headers** | SEC-HEADERS-01 | 8+ headers de segurança OWASP | ✅ |
| **CORS** | SEC-HEADERS-02 | Análise de política de origem cruzada | ✅ |
| **Cache Control** | SEC-HEADERS-03 | Cache de dados sensíveis | ✅ |
| **Rate Limiting (público)** | SEC-RATE-01 | 100 requisições ao endpoint /produtos | ✅ |
| **Rate Limiting (login)** | SEC-RATE-02 | 30 tentativas de login | ✅ |
| **Rate Limiting (cadastro)** | SEC-RATE-03 | 20 criações de usuário | ✅ |

---

##  Arquitetura

```
security-testing/
├── src/
│   ├── client/
│   │   └── ApiClient.ts          # Cliente HTTP com autenticação
│   ├── fixtures/
│   │   └── auth.fixture.ts        # Fixtures: admin e usuário comum
│   ├── tests/
│   │   ├── injection.spec.ts      # SQLi, XSS, Path Traversal, NoSQLi
│   │   ├── auth.spec.ts           # Brute force, RBAC, token, enum
│   │   ├── headers.spec.ts        # OWASP Secure Headers, CORS
│   │   └── rate-limiting.spec.ts  # Rate limiting por endpoint
│   └── utils/
│       └── allure-helper.ts       # Métricas e evidências Allure
├── zap/
│   ├── zap-baseline-scan.sh       # Scan passivo OWASP ZAP
│   └── zap-api-scan.sh            # Scan API OWASP ZAP (OpenAPI)
├── imagem/
│   └── banner.webp                # Banner do repositório
├── playwright.config.ts           # Configuração Playwright
├── tsconfig.json                  # TypeScript config
├── .eslintrc.js                   # ESLint + Prettier
├── .nycrc.json                    # Cobertura de código
└── package.json                   # Dependências e scripts
```

---

## 🚀 Comandos

| Comando | Descrição |
|---------|-----------|
| `npm run test:security` | Executa todos os testes de segurança |
| `npm run test:injection` | Apenas testes de injeção (SQL, XSS, Path, NoSQL) |
| `npm run test:auth` | Apenas testes de autenticação/autorização |
| `npm run test:headers` | Apenas testes de cabeçalhos HTTP |
| `npm run test:rate-limit` | Apenas testes de rate limiting |
| `npm run test:zap` | Scan OWASP ZAP baseline |
| `npm run test:zap:api` | Scan OWASP ZAP API (OpenAPI) |
| `npm run test:all` | Playwright + ZAP |
| `npm run report:allure` | Gera relatório Allure |
| `npm run coverage` | Relatório de cobertura |

---

##  Cenários de Teste

### 🔴 Injeção (CT-SEC)

| ID | Teste | Payloads |
|----|-------|----------|
| CT-SEC-01 | SQL Injection | `' OR '1'='1`, `' UNION SELECT * --`, `'; DROP TABLE --` |
| CT-SEC-02 | XSS | `<script>alert('XSS')</script>`, `<img src=x onerror=...>` |
| CT-SEC-03 | Path Traversal | `../../../etc/passwd`, `%2e%2e%2fetc%2fpasswd` |
| CT-SEC-10 | NoSQL Injection | `{ "$ne": null }`, `{ "$regex": ".*" }` |

### 🔴 Autenticação e Autorização (SEC-AUTH)

| ID | Teste | Expectativa |
|----|-------|-------------|
| SEC-AUTH-01 | Brute Force (10 tentativas) | 429 ou 403 após múltiplas falhas |
| SEC-AUTH-02 | RBAC — Usuário comum cria produto | 403 Forbidden |
| SEC-AUTH-03 | Token inválido (8 formatos) | 401 Unauthorized |
| SEC-AUTH-04 | Endpoint protegido sem token | 401 Unauthorized |
| SEC-AUTH-05 | User Enumeration | Mesma mensagem para user existente/inexistente |
| SEC-AUTH-06 | Horizontal Privilege Escalation | 403 ao acessar dados de outro usuário |

### 🟡 Headers HTTP (SEC-HEADERS)

| ID | Header | Valor Esperado |
|----|--------|----------------|
| SEC-HEADERS-01 | X-Frame-Options | `DENY` ou `SAMEORIGIN` |
| SEC-HEADERS-01 | X-Content-Type-Options | `nosniff` |
| SEC-HEADERS-01 | Content-Security-Policy | Definido |
| SEC-HEADERS-01 | Strict-Transport-Security | `max-age` definido |
| SEC-HEADERS-01 | Referrer-Policy | `strict-origin` ou similar |
| SEC-HEADERS-02 | Access-Control-Allow-Origin | Não deve ser `*` |
| SEC-HEADERS-03 | Cache-Control | `no-store` para dados sensíveis |

### 🟡 Rate Limiting (SEC-RATE)

| ID | Endpoint | Requisições | Expectativa |
|----|----------|-------------|-------------|
| SEC-RATE-01 | GET /produtos | 100 em 10s | 429 detectado |
| SEC-RATE-02 | POST /login | 30 tentativas | 429 detectado |
| SEC-RATE-03 | POST /usuarios | 20 criações | 429 detectado |

---

##  OWASP ZAP

O projeto inclui scripts prontos para execução do **OWASP ZAP** via Docker:

```bash
# Scan passivo (baseline)
npm run test:zap

# Scan ativo via API (OpenAPI)
npm run test:zap:api
```

Reports gerados em `reports/zap-report.html` e `reports/zap-report.xml`.

---

##  Relatórios

| Tipo | Comando | Saída |
|------|---------|-------|
| Allure HTML | `npm run report:allure` | `allure-report/index.html` |
| Playwright HTML | `npx playwright show-report` | `playwright-report/index.html` |
| Cobertura | `npm run coverage` | `coverage/` |
| OWASP ZAP | `npm run test:zap` | `reports/zap-report.html` |

---

##  Mapeamento OWASP

| Classe de Teste | OWASP Top 10 (2021) | ASVS |
|-----------------|---------------------|------|
| SQL Injection | A03:2021 — Injection | V5.3 |
| XSS | A03:2021 — Injection | V5.1 |
| Path Traversal | A01:2021 — Broken Access Control | V4.1 |
| NoSQL Injection | A03:2021 — Injection | V5.3 |
| Brute Force | A07:2021 — Identification & Auth Failures | V2.2 |
| RBAC | A01:2021 — Broken Access Control | V4.1 |
| Token Invalido | A07:2021 — Identification & Auth Failures | V2.1 |
| User Enumeration | A07:2021 — Identification & Auth Failures | V2.3 |
| Secure Headers | A05:2021 — Security Misconfiguration | V14.4 |
| CORS | A05:2021 — Security Misconfiguration | V14.4 |
| Rate Limiting | A07:2021 — Identification & Auth Failures | V2.2 |

---

##  Configuração

```bash
# Instalar dependências
npm install

# Instalar Chromium (Playwright)
npx playwright install chromium

# Executar todos os testes
npm run test:security

# Gerar relatório Allure
npm run report:allure
```

---

##  Licença

MIT

---

<div align="center">

**Testando segurança para construir software mais confiável.**

</div>
