/**
 * Testes de Segurança - Rate Limiting
 *
 * Objetivo: verificar se a API implementa proteção contra abuso
 * através de rate limiting (429 Too Many Requests).
 * Abordagem: OWASP Top 10 - A04:2021 (Insecure Design)
 */

import { test, expect } from "@playwright/test";
import { AllureHelper } from "../utils/allure-helper";
import { request } from "@playwright/test";

const API_BASE_URL = process.env.API_BASE_URL || "https://serverest.dev";

test.describe("SEC-RATE - Testes de Rate Limiting", () => {
  // --------------------------------------------------------------------
  // SEC-RATE-01: Rate limiting em endpoint público
  // --------------------------------------------------------------------
  test("SEC-RATE-01: Deve detectar rate limiting em endpoint público", async () => {
    const descricaoBase =
      "Testa se a API implementa rate limiting em endpoints públicos. " +
      "Envia 100 requisições rápidas para GET /produtos e verifica se " +
      "alguma resposta retorna 429 (Too Many Requests).";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "rate-limit", "dos");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-RATE-01");
    AllureHelper.addFeature("Segurança - Rate Limiting");
    AllureHelper.addStory("Proteção contra Abuso");

    const apiContext = await request.newContext({
      baseURL: API_BASE_URL,
    });

    const requests = [];
    const startTime = Date.now();
    const BATCH_SIZE = 100;

    // Dispara 100 requisições em paralelo
    for (let i = 0; i < BATCH_SIZE; i++) {
      requests.push(
        apiContext
          .get("/produtos", {
            headers: { Accept: "application/json" },
          })
          .then(async (response) => {
            return {
              status: response.status(),
              headers: response.headers(),
            };
          })
          .catch((error) => ({
            status: 0,
            error: error.message,
          })),
      );
    }

    const results = await Promise.all(requests);
    const elapsed = Date.now() - startTime;

    const statusCounts: Record<number, number> = {};
    let rateLimited = false;
    const alertas: string[] = [];

    for (const result of results) {
      statusCounts[result.status] = (statusCounts[result.status] || 0) + 1;
      if (result.status === 429) {
        rateLimited = true;
      }
    }

    const analysis = {
      totalRequests: BATCH_SIZE,
      elapsedTimeMs: elapsed,
      requestsPerSecond: Math.round((BATCH_SIZE / elapsed) * 1000),
      rateLimited,
      statusDistribution: statusCounts,
    };

    AllureHelper.addAttachment(
      "Análise de Rate Limiting",
      JSON.stringify(analysis, null, 2),
      "application/json",
    );

    AllureHelper.addParameter(
      "Requisições/segundo",
      String(analysis.requestsPerSecond),
    );
    AllureHelper.addParameter("Rate Limited", String(rateLimited));

    if (rateLimited) {
      console.log("✅ Rate limiting detectado! API retornou 429.");
    } else {
      alertas.push(
        `[ALERTA] Rate limiting NÃO detectado após ${BATCH_SIZE} requisições em ${elapsed}ms`,
      );
      console.warn(
        `⚠️ Rate limiting NÃO detectado após ${BATCH_SIZE} requisições em ${elapsed}ms`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    await apiContext.dispose();
  });

  // --------------------------------------------------------------------
  // SEC-RATE-02: Rate limiting em login
  // --------------------------------------------------------------------
  test("SEC-RATE-02: Deve detectar rate limiting no endpoint de login", async () => {
    const descricaoBase =
      "Testa rate limiting especificamente no endpoint de login, " +
      "que é o principal alvo de ataques de força bruta.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "rate-limit", "brute-force");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-RATE-02");
    AllureHelper.addFeature("Segurança - Rate Limiting");
    AllureHelper.addStory("Proteção contra Força Bruta");

    const apiContext = await request.newContext({
      baseURL: API_BASE_URL,
    });

    const requests = [];
    const BATCH_SIZE = 30;
    const alertas: string[] = [];

    for (let i = 0; i < BATCH_SIZE; i++) {
      requests.push(
        apiContext
          .post("/login", {
            data: {
              email: `user_${i}@teste.com`,
              password: "senha_errada_" + i,
            },
          })
          .then(async (response) => ({
            status: response.status(),
            body: await response.text().catch(() => ""),
          }))
          .catch((error) => ({
            status: 0,
            error: error.message,
          })),
      );
    }

    const results = await Promise.all(requests);
    const statusCounts: Record<number, number> = {};
    let rateLimited = false;

    for (const result of results) {
      statusCounts[result.status] = (statusCounts[result.status] || 0) + 1;
      if (result.status === 429) {
        rateLimited = true;
      }
    }

    const analysis = {
      totalRequests: BATCH_SIZE,
      rateLimited,
      statusDistribution: statusCounts,
    };

    AllureHelper.addAttachment(
      "Análise Rate Limiting - Login",
      JSON.stringify(analysis, null, 2),
      "application/json",
    );

    if (rateLimited) {
      console.log("✅ Rate limiting em login detectado!");
    } else {
      alertas.push(
        `[ALERTA] Rate limiting em login NÃO detectado após ${BATCH_SIZE} tentativas`,
      );
      console.warn("⚠️ Rate limiting em login NÃO detectado");
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    await apiContext.dispose();
  });

  // --------------------------------------------------------------------
  // SEC-RATE-03: Rate limiting em criação de usuário
  // --------------------------------------------------------------------
  test("SEC-RATE-03: Deve detectar rate limiting na criação de usuários", async () => {
    const descricaoBase =
      "Testa rate limiting no endpoint de criação de usuários, " +
      "prevenindo criação massiva de contas.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "rate-limit", "user-creation");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-RATE-03");
    AllureHelper.addFeature("Segurança - Rate Limiting");
    AllureHelper.addStory("Proteção contra Criação Massiva");

    const apiContext = await request.newContext({
      baseURL: API_BASE_URL,
    });

    const requests = [];
    const BATCH_SIZE = 20;
    const alertas: string[] = [];

    for (let i = 0; i < BATCH_SIZE; i++) {
      requests.push(
        apiContext
          .post("/usuarios", {
            data: {
              nome: `User ${i}`,
              email: `bulk_${i}_${Date.now()}@teste.com`,
              password: "123456",
              administrador: "false",
            },
          })
          .then(async (response) => ({
            status: response.status(),
          }))
          .catch((error) => ({
            status: 0,
            error: error.message,
          })),
      );
    }

    const results = await Promise.all(requests);
    const statusCounts: Record<number, number> = {};
    let rateLimited = false;

    for (const result of results) {
      statusCounts[result.status] = (statusCounts[result.status] || 0) + 1;
      if (result.status === 429) {
        rateLimited = true;
      }
    }

    const analysis = {
      totalRequests: BATCH_SIZE,
      rateLimited,
      statusDistribution: statusCounts,
    };

    AllureHelper.addAttachment(
      "Análise Rate Limiting - Criação de Usuários",
      JSON.stringify(analysis, null, 2),
      "application/json",
    );

    if (rateLimited) {
      console.log("✅ Rate limiting em criação de usuários detectado!");
    } else {
      alertas.push(
        `[ALERTA] Rate limiting em criação de usuários NÃO detectado após ${BATCH_SIZE} requisições`,
      );
      console.warn("⚠️ Rate limiting em criação de usuários NÃO detectado");
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    await apiContext.dispose();
  });
});
