# Dashboard de Maturidade de Segurança

API alvo: [ServeRest](https://serverest.dev)
Data da última execução: 2026-08-05
Total de cenários: 49 (43 segurança + 6 contrato)

---

## Notas por Categoria OWASP

| Categoria OWASP | Nota | Status | Resumo |
|-----------------|------|--------|--------|
| A01:2021 - Broken Access Control | 5/10 | Parcial | RBAC funciona (403 ao criar produto), mas IDOR permite listar usuários e acessar carrinhos alheios. Mass Assignment aceita campos calculados. |
| A02:2021 - Cryptographic Failures | 3/10 | Crítico | Senha retornada em texto plano na consulta GET. Sem política de senha (aceita 1 caractere). JWT usa HS256. HTTPS ativo. |
| A03:2021 - Injection | 2/10 | Crítico | 7 payloads XSS armazenados sem sanitização. Payloads NoSQL processados (embora sem bypass confirmado). SQL e Path Traversal sem evidências de sucesso. |
| A04:2021 - Insecure Design | 0/10 | Crítico | Nenhum rate limiting em qualquer endpoint. Race condition não bloqueia compras simultâneas. |
| A05:2021 - Security Misconfiguration | 4/10 | Alerta | CORS permite qualquer origem (*). Cache sem no-store. Headers OWASP ausentes em múltiplos endpoints (CSP, Referrer-Policy, Permissions-Policy). |
| A06:2021 - Vulnerable Components | 5/10 | Alerta | Header Server expõe Google Frontend. Stack trace não vaza, mas 3 headers de segurança modernos ausentes. |
| A07:2021 - Auth Failures | 4/10 | Alerta | Sem rate limiting no login. Timing attack sem significância estatística. Token inválido rejeitado corretamente. Domínios temporários permitidos no cadastro. |
| A08:2021 - Software Integrity | 6/10 | Parcial | JWT com algoritmo none rejeitado. Campo desconto aceito na criação de produto. Race condition em update de cadastro sem inconsistência detectada. |

---

## Gráfico Resumo
A01: Broken Access Control ████████████░░░░░░░░ 5/10
A02: Cryptographic Failures ██████░░░░░░░░░░░░░░ 3/10
A03: Injection ████░░░░░░░░░░░░░░░░ 2/10
A04: Insecure Design ░░░░░░░░░░░░░░░░░░░░ 0/10
A05: Misconfiguration ████████░░░░░░░░░░░░ 4/10
A06: Vulnerable Components ██████████░░░░░░░░░░ 5/10
A07: Auth Failures ████████░░░░░░░░░░░░ 4/10
A08: Software Integrity ████████████░░░░░░░░ 6/10

Nota média: **3.6/10** — API com vulnerabilidades críticas, não recomendada para produção sem correções.

---

## O que esses números significam

- **0-3:** Vulnerabilidade confirmada e explorável. Correção urgente.
- **4-6:** Alerta ou proteção parcial. Requer atenção.
- **7-9:** Boa proteção, com pequenos pontos de melhoria.
- **10:** Controle implementado corretamente, sem falhas detectadas.

---

## Metodologia

Cada categoria foi testada com cenários reais (não apenas checklists teóricos). As notas refletem o resultado dos testes automatizados disponíveis no diretório `src/tests/security/` deste repositório. O relatório completo com evidências está disponível no Allure Report.

Relatório Allure ao vivo: [https://j0hnweider.github.io/security-testing](https://j0hnweider.github.io/security-testing)
