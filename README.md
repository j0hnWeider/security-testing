[![Security Tests](https://github.com/j0hnWeider/security-testing/actions/workflows/security-tests.yml/badge.svg)](https://github.com/j0hnWeider/security-testing/actions/workflows/security-tests.yml)

<div align="center">
  <img src="imagem/banner.webp" alt="Security Testing Banner" width="100%" style="max-width: 800px; border-radius: 12px;">
</div>

<div align="center">

# Security Testing
**Portfólio de Automação e Segurança em APIs**

<p align="center">
  <img src="https://img.shields.io/badge/Playwright-45BA63?style=flat-square&logo=playwright&logoColor=white"/>
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP_Top_10-000000?style=flat-square"/>
  <img src="https://img.shields.io/github/license/j0hnWeider/security-testing?style=flat-square"/>
  <img src="https://img.shields.io/badge/Status-Em%20Estudo-blue?style=flat-square"/>
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

**Ação tomada:** Criei testes com payloads reais de SQL, NoSQL, XSS e Path Traversal. Em vez de apenas listar vetores genéricos, modelei cenários como **buscas por produtos contendo injeção** e **cadastros com scripts maliciosos no nome do usuário** para validar a sanitização real da aplicação.

### 2. Autenticação e Controle de Acesso
> *"O sistema realmente sabe quem é o usuário? Um usuário comum consegue forçar acesso a rotas de administrador ou a dados de outro usuário apenas mudando o ID na requisição?"*

**Ação tomada:** Estruturei testes para validar a troca de tokens malformados, a ausência de autenticação, e cenários críticos de negócio como **um usuário comum tentar criar um produto** (que deve retornar 403), e **um usuário tentar acessar ou alterar dados de outro usuário apenas alterando parâmetros da URL** (escalonamento horizontal).

### 3. Configuração do Servidor
> *"O servidor está configurado para evitar ataques simples de engrenagem? As políticas de cache, CORS e limites de requisição estão bem ajustadas para evitar sobrecarga ou vazamento de dados?"*

**Ação tomada:** Implementei testes para verificar os headers OWASP (como `X-Frame-Options` e `CSP`), validar que o CORS não permite origens genéricas (`*`) e forçar o Rate Limiting com **volumes de requisições próximos ao que um ataque de força bruta real faria** para validar a resiliência da infraestrutura.

---

## O que a execução dos meus testes revelou

Na última execução, a suíte rodou 16 cenários e evidenciou falhas críticas:

- **Falha de Sanitização:** 7 vulnerabilidades de XSS detectadas (a API reflete scripts maliciosos na resposta).
- **Falta de Rate Limiting:** Nenhum dos endpoints principais bloqueia tentativas repetidas de requisição.
- **Configurações permissivas:** CORS liberado para qualquer origem (`*`) e Cache sem `no-store` para dados sensíveis.

---

## Sobre a implementação técnica

Este projeto foi construído inteiramente com **Playwright e TypeScript**, com foco em boas práticas de engenharia de software:

- **Organização de código:** Separação clara entre o cliente HTTP, fixtures de dados e os specs de teste, o que facilita a manutenção e escalabilidade.
- **Integração contínua:** Pipeline configurada no GitHub Actions que executa a suíte automaticamente a cada push.
- **Métricas:** Uso do `nyc` para rastrear a cobertura de código (atualmente em 84,9%), garantindo que o mínimo de linhas fiquem sem teste.
- **Geração de evidências:** Os testes não só rodam, como geram relatórios HTML interativos que documentam claramente o comportamento da API e as falhas encontradas.

---

## Como reproduzir os testes e gerar as evidências localmente

Para verificar o projeto na prática, clone o repositório e execute os comandos abaixo:

```bash
# Instalar dependências
npm install
npx playwright install chromium

# Executar a suíte completa com cobertura
npm run test:coverage

# Abrir o relatório de evidências (Playwright)
npx playwright show-report reports/playwright-report
```

Relatórios gerados localmente na sua máquina:

- `playwright-report/index.html`: Relatório interativo do Playwright.
- `allure-report/index.html`: Métricas e evidências do Allure.
- `reports/zap-report.html`: Scan do OWASP ZAP via Docker.

---

## Estrutura de código

```
security-testing/
├── src/
│   ├── client/
│   │   └── ApiClient.ts     # Gerencia requisições HTTP e tokens de forma centralizada
│   ├── fixtures/
│   │   └── auth.fixture.ts  # Fixtures reutilizáveis para usuário admin e comum
│   └── tests/               # Suíte baseada em cenários reais de negócio
│       ├── injection.spec.ts     # Valida sanitização (XSS, SQLi) com contextos reais de busca e cadastro
│       ├── auth.spec.ts          # Valida RBAC, escalonamento horizontal e token inválido
│       ├── headers.spec.ts       # Valida Headers OWASP e configuração de CORS
│       └── rate-limiting.spec.ts # Valida limites reais de requisições por endpoint
├── playwright.config.ts     # Configuração do Playwright (timeouts, workers, etc.)
└── .nycrc.json              # Configuração de métricas de cobertura
```

---

## Principais comandos

```bash
npm run test:security    # Executa todos os cenários
npm run test:auth        # Valida RBAC, tokens e vazamentos de dados
npm run test:injection   # Valida sanitização de inputs em cenários reais
npm run test:headers     # Valida configuração de CORS e Headers OWASP
npm run test:rate-limit  # Valida proteção contra força bruta e DoS
npm run coverage         # Relatório de cobertura de código
npm run test:zap         # Scan OWASP ZAP via Docker (análise passiva)
```

---

## Minha visão sobre próximos passos

Este projeto é vivo. A próxima fase é simular um ciclo de correção e regressão: aplicar patches na API, reexecutar a suíte, e gerar novas evidências que comprovem a eficácia das correções. Isso demonstra um fluxo completo de QA Engineering: **Detecção -> Report -> Correção -> Validação**.

---

MIT License - John Weider
