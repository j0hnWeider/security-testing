/**
 * Testes de Segurança - Componentes Vulneráveis e Desatualizados
 *
 * Objetivo: identificar exposição de informações sobre a stack tecnológica
 * e verificar se a API revela detalhes que facilitam ataques direcionados.
 * Abordagem: OWASP Top 10 - A06:2021 (Vulnerable and Outdated Components)
 *            OWASP ASVS V14.2 (Dependency Analysis)
 */

import { test, request, APIResponse } from "@playwright/test";
import { createAuthenticatedClient } from "../fixtures/auth.fixture";
import { ApiClient } from "../client/ApiClient";
import { AllureHelper } from "../utils/allure-helper";

test.describe
  .serial("SEC-OUTDATED - Componentes Vulneráveis e Desatualizados", () => {
  let adminClient: ApiClient;
  let baseUrl: string;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
    baseUrl = process.env.API_BASE_URL || "https://serverest.dev";
  });

  test("SEC-OUTDATED-01: API não deve expor header Server com versão", async () => {
    const descricaoBase =
      "Verifica se o header 'Server' está presente na resposta e se revela " +
      "a versão exata do software utilizado. Headers como 'Server: nginx/1.18.0' " +
      "ou 'X-Powered-By: Express/4.17.1' facilitam ataques direcionados contra " +
      "versões específicas com CVEs conhecidas.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "outdated", "information-disclosure");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-OUTDATED-01");
    AllureHelper.addFeature("Segurança - Componentes Desatualizados");
    AllureHelper.addStory("Exposição de Versão do Servidor");

    const tempContext = await request.newContext({ baseURL: baseUrl });
    const response = await tempContext.get("/");
    const headers = response.headers();

    const sensitiveHeaders = [
      {
        name: "server",
        risk: "Revela o servidor web e potencialmente sua versão",
      },
      { name: "x-powered-by", risk: "Revela a tecnologia backend e versão" },
      { name: "x-aspnet-version", risk: "Revela versão do ASP.NET" },
      { name: "x-aspnetmvc-version", risk: "Revela versão do ASP.NET MVC" },
      { name: "x-runtime", risk: "Revela tempo de execução da aplicação" },
      { name: "x-generator", risk: "Revela o gerador/framework utilizado" },
    ];

    const encontrados: Array<{
      header: string;
      valor: string;
      risco: string;
    }> = [];

    for (const header of sensitiveHeaders) {
      const value = headers[header.name];
      if (value) {
        encontrados.push({
          header: header.name,
          valor: value,
          risco: header.risk,
        });
        console.log(`[OUTDATED] Header exposto: ${header.name}: ${value}`);
      }
    }

    const alertas: string[] = [];

    await AllureHelper.addAttachment(
      "Headers Analisados",
      JSON.stringify(
        {
          todos_headers: headers,
          headers_sensiveis_encontrados: encontrados,
        },
        null,
        2,
      ),
      "application/json",
    );

    if (encontrados.length > 0) {
      const nomes = encontrados.map((e) => e.header).join(", ");
      alertas.push(
        `[ALERTA] ${encontrados.length} headers sensíveis expostos: ${nomes}`,
      );
      console.log(`[ALERTA] ${encontrados.length} headers sensíveis expostos.`);
      await AllureHelper.addAttachment(
        "Alerta: Headers Sensíveis Expostos",
        JSON.stringify(
          {
            alerta: "API expõe informações sobre a stack tecnológica",
            headers_encontrados: encontrados,
            recomendacao:
              "Remover ou ofuscar headers que revelem versões de software",
          },
          null,
          2,
        ),
        "application/json",
      );
    }

    const serverHeader = headers["server"];
    const hasVersionNumber = serverHeader && /\d+\.\d+/.test(serverHeader);

    if (hasVersionNumber) {
      alertas.push(`[ALERTA] Header Server contém versão: ${serverHeader}`);
      console.log(
        `[ALERTA] Header 'Server' contém número de versão: ${serverHeader}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    await tempContext.dispose();
  });

  test("SEC-OUTDATED-02: Respostas de erro não devem expor stack trace", async () => {
    const descricaoBase =
      "Provoca erros na API e analisa as respostas em busca de stack traces, " +
      "nomes de arquivos, paths do servidor ou mensagens de debug. " +
      "Essas informações são um guia para atacantes mapearem a infraestrutura.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "outdated", "information-disclosure");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-OUTDATED-02");
    AllureHelper.addFeature("Segurança - Componentes Desatualizados");
    AllureHelper.addStory("Exposição de Stack Trace");

    const errorEndpoints = [
      { method: "GET", path: "/usuarios/id_inexistente_formato_invalido" },
      { method: "GET", path: "/produtos/-1" },
      { method: "POST", path: "/login", body: {} as Record<string, unknown> },
      {
        method: "POST",
        path: "/usuarios",
        body: {} as Record<string, unknown>,
      },
      {
        method: "PUT",
        path: "/usuarios/id_inexistente",
        body: { nome: "teste" } as Record<string, unknown>,
      },
    ];

    const suspiciousPatterns = [
      {
        pattern: /at\s+\w+\.\w+:\d+:\d+/i,
        descricao: "Stack trace (formato Node.js)",
      },
      {
        pattern: /\.js:\d+:\d+/i,
        descricao: "Referência a arquivo .js com linha",
      },
      {
        pattern: /\.ts:\d+:\d+/i,
        descricao: "Referência a arquivo .ts com linha",
      },
      { pattern: /\/var\/www\//i, descricao: "Path do servidor Linux" },
      { pattern: /C:\\inetpub\\/i, descricao: "Path do servidor Windows/IIS" },
      { pattern: /\/home\/\w+\//i, descricao: "Path home de usuário" },
      { pattern: /node_modules\//i, descricao: "Referência a node_modules" },
      { pattern: /Error:\s+/i, descricao: "Mensagem de erro detalhada" },
      { pattern: /SQL\s*(syntax|error|exception)/i, descricao: "Erro de SQL" },
      {
        pattern: /MongoError|MongoServerError/i,
        descricao: "Erro específico do MongoDB",
      },
      { pattern: /express\//i, descricao: "Versão do Express" },
    ];

    const vazamentos: Array<{
      endpoint: string;
      status: number;
      padrao: string;
      trecho: string;
    }> = [];

    for (const endpoint of errorEndpoints) {
      let response: APIResponse;

      if (endpoint.method === "GET") {
        response = await adminClient.get(endpoint.path);
      } else {
        response = await adminClient.post(endpoint.path, endpoint.body || {});
      }

      if (response.status() >= 200 && response.status() < 500) {
        continue;
      }

      const body = await response.text();

      for (const pattern of suspiciousPatterns) {
        if (pattern.pattern.test(body)) {
          const match = body.match(pattern.pattern);
          vazamentos.push({
            endpoint: `${endpoint.method} ${endpoint.path}`,
            status: response.status(),
            padrao: pattern.descricao,
            trecho: match ? match[0] : "N/A",
          });
        }
      }
    }

    const alertas: string[] = [];

    await AllureHelper.addAttachment(
      "Análise de Vazamento em Erros",
      JSON.stringify(
        {
          total_vazamentos: vazamentos.length,
          vazamentos: vazamentos,
        },
        null,
        2,
      ),
      "application/json",
    );

    if (vazamentos.length > 0) {
      alertas.push(
        `[ALERTA] ${vazamentos.length} vazamentos de informação em respostas de erro`,
      );
      console.log(
        `[ALERTA] ${vazamentos.length} vazamentos de informação em respostas de erro.`,
      );
      vazamentos.forEach((v) => {
        console.log(`  - ${v.endpoint}: ${v.padrao}`);
      });

      await AllureHelper.addAttachment(
        "Alerta: Stack Trace Exposto",
        JSON.stringify(
          {
            alerta: "API vaza informações internas em mensagens de erro",
            vazamentos: vazamentos,
            recomendacao:
              "Configurar tratamento de erros genérico em produção sem detalhes internos",
          },
          null,
          2,
        ),
        "application/json",
      );
    } else {
      console.log("[INFO] Nenhum vazamento de stack trace detectado.");
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-OUTDATED-03: API não deve expor detalhes de bibliotecas em headers de resposta", async () => {
    const descricaoBase =
      "Analisa headers de resposta em múltiplos endpoints para identificar " +
      "padrões que permitam fingerprinting da stack tecnológica.";

    AllureHelper.addSeverity("minor");
    AllureHelper.addTags("security", "outdated", "fingerprinting");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-OUTDATED-03");
    AllureHelper.addFeature("Segurança - Componentes Desatualizados");
    AllureHelper.addStory("Fingerprinting da Stack");

    const endpoints = [
      { method: "GET", path: "/" },
      { method: "GET", path: "/produtos" },
      { method: "GET", path: "/usuarios" },
      {
        method: "POST",
        path: "/login",
        body: { email: "teste@teste.com", password: "123" } as Record<
          string,
          unknown
        >,
      },
    ];

    const fingerprintIndicators: string[] = [];
    const allHeaders: Array<{
      endpoint: string;
      status: number;
      headers: Record<string, string>;
    }> = [];

    for (const endpoint of endpoints) {
      let response: APIResponse;

      if (endpoint.method === "GET") {
        response = await adminClient.get(endpoint.path);
      } else {
        response = await adminClient.post(endpoint.path, endpoint.body || {});
      }

      const headers = response.headers();
      allHeaders.push({
        endpoint: `${endpoint.method} ${endpoint.path}`,
        status: response.status(),
        headers: headers,
      });

      const setCookie = headers["set-cookie"];
      if (setCookie) {
        if (setCookie.includes("connect.sid")) {
          fingerprintIndicators.push(
            `Cookie connect.sid detectado em ${endpoint.path} -> Possível Express/Connect`,
          );
        }
      }

      const contentType = headers["content-type"];
      if (contentType && contentType.includes("application/vnd.")) {
        fingerprintIndicators.push(
          `Content-Type customizado em ${endpoint.path} -> ${contentType}`,
        );
      }
    }

    const alertas: string[] = [];

    await AllureHelper.addAttachment(
      "Headers por Endpoint",
      JSON.stringify(allHeaders, null, 2),
      "application/json",
    );

    if (fingerprintIndicators.length > 0) {
      alertas.push(
        `[ALERTA] ${fingerprintIndicators.length} indicadores de fingerprinting encontrados`,
      );
      console.log(
        `[ALERTA] ${fingerprintIndicators.length} indicadores de fingerprinting encontrados.`,
      );
      fingerprintIndicators.forEach((indicator) => {
        console.log(`  - ${indicator}`);
      });

      await AllureHelper.addAttachment(
        "Alerta: Fingerprinting Possível",
        JSON.stringify(
          {
            alerta: "Headers permitem identificação da stack tecnológica",
            indicadores: fingerprintIndicators,
            recomendacao:
              "Ocultar ou padronizar headers que identifiquem a tecnologia utilizada",
          },
          null,
          2,
        ),
        "application/json",
      );
    } else {
      console.log("[INFO] Nenhum indicador claro de fingerprinting detectado.");
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-OUTDATED-04: Verificar ausência de headers de segurança como indicador de versão desatualizada", async () => {
    const descricaoBase =
      "A ausência de headers de segurança modernos (como Content-Security-Policy, " +
      "X-Content-Type-Options, Strict-Transport-Security) pode indicar que o " +
      "framework ou configuração do servidor está desatualizado.";

    AllureHelper.addSeverity("minor");
    AllureHelper.addTags("security", "outdated", "missing-headers");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-OUTDATED-04");
    AllureHelper.addFeature("Segurança - Componentes Desatualizados");
    AllureHelper.addStory("Headers Ausentes - Indicador de Desatualização");

    const tempContext = await request.newContext({ baseURL: baseUrl });
    const response = await tempContext.get("/");
    const headers = response.headers();

    const modernHeaders = [
      "content-security-policy",
      "x-content-type-options",
      "x-frame-options",
      "strict-transport-security",
      "x-xss-protection",
      "referrer-policy",
      "permissions-policy",
    ];

    const ausentes: string[] = [];
    const presentes: string[] = [];

    for (const header of modernHeaders) {
      if (headers[header]) {
        presentes.push(`${header}: ${headers[header]}`);
      } else {
        ausentes.push(header);
      }
    }

    const alertas: string[] = [];

    await AllureHelper.addAttachment(
      "Análise de Headers Modernos",
      JSON.stringify(
        {
          headers_presentes: presentes,
          headers_ausentes: ausentes,
          total_ausentes: ausentes.length,
          total_verificados: modernHeaders.length,
        },
        null,
        2,
      ),
      "application/json",
    );

    console.log(
      `[OUTDATED] Headers presentes: ${presentes.length}/${modernHeaders.length}`,
    );
    console.log(`[OUTDATED] Headers ausentes: ${ausentes.join(", ")}`);

    if (ausentes.length >= 4) {
      alertas.push(
        `[ALERTA] ${ausentes.length} headers de segurança ausentes: ${ausentes.join(", ")}`,
      );
      console.log(
        `[ALERTA] ${ausentes.length} headers de segurança modernos estão ausentes. ` +
          "Isso pode indicar configuração desatualizada.",
      );
      await AllureHelper.addAttachment(
        "Alerta: Headers Modernos Ausentes",
        JSON.stringify(
          {
            alerta: "Grande número de headers de segurança ausentes",
            headers_ausentes: ausentes,
            possivel_causa:
              "Framework ou servidor desatualizado que não inclui headers modernos por padrão",
            recomendacao:
              "Atualizar configuração do servidor para incluir headers de segurança recomendados pelo OWASP",
          },
          null,
          2,
        ),
        "application/json",
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    await tempContext.dispose();
  });
});
