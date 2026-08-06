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
  <img src="https://img.shields.io/badge/k6-Performance-7D64FF?style=for-the-badge&logo=k6&logoColor=white"/>
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

**Ação tomada:** Além de testar tokens malformados e ausência de autenticação, implementei uma suíte completa de **IDOR** (Insecure Direct Object References) e **Mass Assignment** para verificar se um usuário comum consegue acessar, editar ou promover recursos que pertencem a outros.

### 3. Criptografia e Proteção de Dados
> *"As senhas trafegam em texto plano? Os tokens JWT utilizam algoritmos seguros e têm expiração definida? A API impõe políticas mínimas de senha?"*

**Ação tomada:** Desenvolvi testes que decodificam tokens JWT para inspecionar o algoritmo (`alg`) e a presença de `exp`, validam que senhas não vazam nas respostas de criação e consulta, verificam a política de senha e confirmam o uso de HTTPS.

### 4. Lógica de Negócio e Concorrência
> *"O que acontece se dois usuários comprarem o último item do estoque exatamente ao mesmo tempo?"*

**Ação tomada:** Criei cenários de **race condition** para disparar compras simultâneas e verificar se o estoque fica negativo. Isso vai além de testes de segurança tradicionais e entra em qualidade de negócio.

### 5. Performance sob Estresse
> *"Como a API se comporta sob carga? Um ataque de força bruta prejudica a experiência de usuários legítimos?"*

**Ação tomada:** Desenvolvi scripts de performance com **k6** e **Node.js puro** que simulam cenários reais: ReDoS, Black Friday com hotspot, carrinhos abandonados, força bruta sob carga e concorrência em escritas.

---

## O que a execução dos meus testes revelou

Na última execução, a suíte rodou **55 cenários** distribuídos em 11 categorias e evidenciou falhas críticas:

| Categoria | Cenários | Principais Achados |
|-----------|----------|---------------------|
| **Autenticação** | 8 | Falta de Rate Limiting, domínios temporários permitidos |
| **IDOR** | 6 | Usuário comum lista todos os usuários, acessa carrinhos alheios |
| **Mass Assignment** | 5 | API aceita `administrador: true`, tipos errados e campos desconhecidos |
| **Criptografia** | 6 | Senha exposta em texto plano na consulta GET, política de senha inexistente |
| **Headers** | 3 | CORS `*`, Cache sem `no-store`, falta de CSP e Referrer-Policy |
| **Injeção** | 4 | 7 payloads XSS armazenados sem sanitização, NoSQL injection processado |
| **Componentes** | 4 | Header Server exposto (`Google Frontend`), falta de headers modernos |
| **Integridade** | 4 | JWT `alg: none` rejeitado, `desconto` injetado via Mass Assignment |
| **Boundary/Edge** | 6 | Payload de 1MB aceito, JSON malformado retorna 500 com stack trace |
| **Contrato** | 4 | Schema validado, mas campo `password` vaza na resposta |
| **Performance** | 8 | Scripts prontos para execução com k6 e Node.js nativo |

---

## Relatório Allure ao vivo

O relatório completo do Allure é publicado automaticamente no GitHub Pages após cada push na branch `main`:

**[https://j0hnweider.github.io/security-testing](https://j0hnweider.github.io/security-testing)**

---

## Sobre a implementação técnica

- **Playwright + TypeScript** para testes de segurança, contrato e boundary.
- **k6 + Node.js** para testes de performance e estresse.
- **GitHub Actions** com pipeline CI/CD que publica relatórios automaticamente.
- Dados sob demanda com timestamp e componente aleatório para idempotência.
- Alertas concatenados nas descrições do Allure e anexos JSON para diagnóstico.

---

## Estrutura de código

```text
security-testing/
├── .github/workflows/ # Pipeline CI/CD e deploy no Pages
├── config/allure/ # Categorias personalizadas do Allure
├── scripts/
│ └── performance/ # Scripts k6 e Node.js para testes de estresse
├── src/
│ ├── client/ # ApiClient centralizado com gerenciamento de token
│ ├── fixtures/ # Fixtures reutilizáveis (admin e usuário comum)
│ ├── tests/
│ │ ├── security/ # Testes de segurança (OWASP, boundary, contrato)
│ │ └── ui/ # Testes de frontend (Juice Shop)
│ └── utils/ # AllureHelper e utilitários
├── playwright.config.ts
├── package.json
├── resultados.md # Dashboard de maturidade de segurança
└── README.md
```

---

## Mapeamento OWASP Top 10 (2021)

| Categoria | Testes |
|-----------|--------|
| **A01:2021 - Broken Access Control** | RBAC, IDOR, Mass Assignment |
| **A02:2021 - Cryptographic Failures** | Senha, JWT, Política de senha, HTTPS |
| **A03:2021 - Injection** | SQLi, XSS, Path Traversal, NoSQLi |
| **A04:2021 - Insecure Design** | Rate Limiting, Race Condition |
| **A05:2021 - Security Misconfiguration** | Headers HTTP, CORS, Cache |
| **A06:2021 - Vulnerable Components** | Server header, Stack trace, Fingerprinting |
| **A07:2021 - Auth Failures** | Brute Force, Token, Enumeração, Timing Attack |
| **A08:2021 - Software Integrity** | JWT `none`, Mass Assignment, Race Condition |

---

## Principais comandos

```bash
npm run test:security    # Todos os 55 cenários
npm run test:auth        # RBAC, tokens, timing attack
npm run test:boundary    # Payload gigante, JSON malformado, Unicode
npm run test:contract    # Validação de schema e status HTTP
npm run test:crypto      # Senha, JWT, política de senha, HTTPS
npm run test:idor        # Acesso indevido a recursos
npm run test:injection   # SQLi, XSS, NoSQLi, Path Traversal
npm run test:integrity   # JWT none, token reuso, campos calculados
npm run test:mass        # Auto-promoção, ID customizado, tipos
npm run test:outdated    # Server header, stack trace, fingerprinting
npm run test:race        # Concorrência em compras
npm run test:rate-limit  # Proteção contra força bruta e DoS
npm run test:ui          # Testes de segurança no frontend
npm run perf:all         # Todos os cenários de performance
```
MIT License - John Weider
