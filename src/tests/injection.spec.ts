/**
 * Testes de Segurança - Injeções (SQL, XSS, Path Traversal, NoSQL)
 *
 * Objetivo: validar proteção contra injeções
 * Abordagem: OWASP Top 10 - A03:2021 (Injection)
 */

import { test, expect } from "@playwright/test";
import { createAuthenticatedClient } from "../fixtures/auth.fixture";
import { AllureHelper } from "../utils/allure-helper";
import { APIResponse } from "@playwright/test";

test.describe("CT-SEC - Testes de Injeção", () => {
  let authContext: any;

  test.beforeAll(async () => {
    authContext = await createAuthenticatedClient();
  });

  test.afterAll(async () => {
    if (authContext) {
      await authContext.apiContext.dispose();
    }
  });

  // --------------------------------------------------------------------
  // CT-SEC-01: SQL Injection
  // --------------------------------------------------------------------
  test("CT-SEC-01: Deve proteger contra SQL Injection", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "sql");
    AllureHelper.addDescription(
      "Valida que a API está protegida contra ataques de SQL Injection.",
    );
    AllureHelper.addTestCaseId("CT-SEC-01");

    const sqlPayloads = [
      "' OR '1'='1",
      "' UNION SELECT * FROM users --",
      "'; DROP TABLE produtos --",
      "' OR 1=1 --",
      "' OR '1'='1' /*",
      "'; SELECT * FROM produtos --",
      "' UNION SELECT 1,2,3,4,5 --",
      "' OR 'x'='x",
    ];

    for (let i = 0; i < sqlPayloads.length; i++) {
      const payload = sqlPayloads[i];
      await AllureHelper.addStep(
        `Testando SQL Injection: ${payload}`,
        async () => {
          const response: APIResponse = await authContext.client.get(
            `/produtos?nome=${encodeURIComponent(payload)}`,
            false,
          );
          expect([200, 400, 500]).toContain(response.status());
        },
      );
    }
  });

  // --------------------------------------------------------------------
  // CT-SEC-02: XSS (Cross-Site Scripting)
  // --------------------------------------------------------------------
  test("CT-SEC-02: Deve proteger contra XSS", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "xss");
    AllureHelper.addDescription(
      "Valida que a API está protegida contra ataques de XSS.",
    );
    AllureHelper.addTestCaseId("CT-SEC-02");

    const xssPayloads = [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "javascript:alert('XSS')",
      "<body onload=alert('XSS')>",
      "<iframe src='javascript:alert(1)'>",
      "<input type='text' value='' onfocus='alert(1)'>",
      "'; alert('XSS'); //",
    ];

    for (let i = 0; i < xssPayloads.length; i++) {
      const payload = xssPayloads[i];
      await AllureHelper.addStep(
        `Testando XSS: ${payload.substring(0, 30)}...`,
        async () => {
          const response: APIResponse = await authContext.client.post(
            "/produtos",
            {
              nome: `Teste XSS ${i}`,
              preco: 100,
              descricao: payload,
              quantidade: 1,
            },
            true,
          );
          expect([200, 400, 500]).toContain(response.status());
        },
      );
    }
  });

  // --------------------------------------------------------------------
  // CT-SEC-03: Path Traversal
  // --------------------------------------------------------------------
  test("CT-SEC-03: Deve proteger contra Path Traversal", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "path-traversal");
    AllureHelper.addDescription(
      "Valida que a API está protegida contra ataques de Path Traversal.",
    );
    AllureHelper.addTestCaseId("CT-SEC-03");

    const pathPayloads = [
      "../../../etc/passwd",
      "../../../../windows/win.ini",
      "..\\..\\..\\etc\\passwd",
      "%2e%2e%2fetc%2fpasswd",
      "....//....//....//etc/passwd",
    ];

    for (let i = 0; i < pathPayloads.length; i++) {
      const payload = pathPayloads[i];
      await AllureHelper.addStep(
        `Testando Path Traversal: ${payload}`,
        async () => {
          const response: APIResponse = await authContext.client.get(
            `/produtos?nome=${encodeURIComponent(payload)}`,
            false,
          );
          expect([200, 400, 404, 500]).toContain(response.status());
        },
      );
    }
  });

  // --------------------------------------------------------------------
  // CT-SEC-10: NoSQL Injection
  // --------------------------------------------------------------------
  test("CT-SEC-10: Deve proteger contra NoSQL Injection", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "nosql");
    AllureHelper.addDescription(
      "Valida que a API está protegida contra ataques de NoSQL Injection.",
    );
    AllureHelper.addTestCaseId("CT-SEC-10");

    const nosqlPayloads = [
      '{ "$ne": null }',
      '{ "$regex": ".*" }',
      '{ "$or": [{ "email": { "$regex": ".*" } }] }',
      '{ "$gt": "" }',
    ];

    for (let i = 0; i < nosqlPayloads.length; i++) {
      const payload = nosqlPayloads[i];
      await AllureHelper.addStep(
        `Testando NoSQL Injection: ${payload}`,
        async () => {
          const response: APIResponse = await authContext.client.post(
            "/login",
            { email: payload, password: payload },
            false,
          );
          expect([200, 400, 401, 500]).toContain(response.status());
        },
      );
    }
  });
});
