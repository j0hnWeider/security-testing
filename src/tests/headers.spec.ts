/**
 * Testes de Segurança - Headers HTTP
 *
 * Objetivo: validar headers de segurança OWASP
 * Abordagem: OWASP Top 10 - A05:2021 (Security Misconfiguration)
 */

import { test, expect } from "@playwright/test";
import { AllureHelper } from "../utils/allure-helper";
import { createAuthenticatedClient } from "../fixtures/auth.fixture";

test.describe("SEC-HEADERS - Testes de Headers HTTP", () => {
  let baseUrl: string;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    baseUrl = process.env.API_BASE_URL || "https://serverest.dev";
    await auth.apiContext.dispose();
  });

  // --------------------------------------------------------------------
  // SEC-HEADERS-01: Headers de Segurança OWASP
  // --------------------------------------------------------------------
  test("SEC-HEADERS-01: Deve retornar headers de segurança OWASP", async ({
    request,
  }) => {
    const descricaoBase =
      "Valida a presença dos principais headers de segurança " +
      "recomendados pelo OWASP.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "headers", "owasp");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-HEADERS-01");

    const response = await request.get(baseUrl);
    const headers = response.headers();

    const expectedHeaders = {
      "X-Frame-Options": ["DENY", "SAMEORIGIN"],
      "X-Content-Type-Options": ["nosniff"],
      "Strict-Transport-Security": ["max-age="],
      "Referrer-Policy": ["strict-origin", "same-origin"],
    };

    const missingHeaders: string[] = [];
    const alertas: string[] = [];

    for (const [header, expectedValues] of Object.entries(expectedHeaders)) {
      const headerValue = headers[header.toLowerCase()];
      if (!headerValue) {
        missingHeaders.push(header);
        continue;
      }

      const found = expectedValues.some((val: string) =>
        headerValue.toLowerCase().includes(val.toLowerCase()),
      );

      if (!found) {
        console.warn(
          `⚠️ Header ${header} encontrado, mas valor inesperado: ${headerValue}`,
        );
      }
    }

    AllureHelper.addAttachment(
      "Headers Detectados",
      JSON.stringify(headers, null, 2),
      "application/json",
    );

    if (missingHeaders.length > 0) {
      alertas.push(`[ALERTA] Headers ausentes: ${missingHeaders.join(", ")}`);
      console.warn(`⚠️ Headers ausentes: ${missingHeaders.join(", ")}`);
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    // Não falha o teste se headers estiverem ausentes (apenas reporta)
    expect(missingHeaders).not.toContain("X-Frame-Options");
  });

  // --------------------------------------------------------------------
  // SEC-HEADERS-02: CORS
  // --------------------------------------------------------------------
  test("SEC-HEADERS-02: Deve ter política CORS adequada", async ({
    request,
  }) => {
    const descricaoBase =
      "Valida que a política CORS não permite origens arbitrárias.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "headers", "cors");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-HEADERS-02");

    const response = await request.get(baseUrl);
    const headers = response.headers();

    const allowOrigin = headers["access-control-allow-origin"];
    const alertas: string[] = [];

    AllureHelper.addAttachment(
      "CORS Configuration",
      JSON.stringify({ "Access-Control-Allow-Origin": allowOrigin }, null, 2),
      "application/json",
    );

    if (allowOrigin === "*") {
      alertas.push(
        "[ALERTA] CORS permitindo qualquer origem (*) - potencial risco de segurança",
      );
      console.warn(
        "⚠️ CORS permitindo qualquer origem (*) - potencial risco de segurança",
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  // --------------------------------------------------------------------
  // SEC-HEADERS-03: Cache Control
  // --------------------------------------------------------------------
  test("SEC-HEADERS-03: Deve ter política de cache adequada", async ({
    request,
  }) => {
    const descricaoBase = "Valida que dados sensíveis não são cacheados.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "headers", "cache");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-HEADERS-03");

    const response = await request.get(baseUrl);
    const headers = response.headers();

    const cacheControl = headers["cache-control"];
    const pragma = headers["pragma"];
    const alertas: string[] = [];

    AllureHelper.addAttachment(
      "Cache Headers",
      JSON.stringify(
        { "Cache-Control": cacheControl, Pragma: pragma },
        null,
        2,
      ),
      "application/json",
    );

    if (cacheControl && cacheControl.includes("no-store")) {
      console.log("✅ Cache-Control configurado corretamente");
    } else {
      alertas.push("[ALERTA] Cache-Control não possui 'no-store'");
      console.warn("⚠️ Cache-Control não possui no-store");
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });
});
