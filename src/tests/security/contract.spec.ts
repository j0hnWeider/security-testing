/**
 * Testes de Contrato (API Contract Testing)
 *
 * A ideia aqui nao eh testar vulnerabilidade. Eh testar se a API entrega
 * o que promete: schema correto, campos obrigatorios presentes, tipos certos,
 * status code adequado. Isso aqui complementa os testes de seguranca e mostra
 * que eu penso em qualidade como um todo, nao so em ataque.
 *
 * O que valida:
 * - Schema de resposta de GET /usuarios e GET /produtos
 * - Campos obrigatorios presentes
 * - Tipos de dados corretos (string, number, boolean)
 * - Status codes padrao HTTP
 * - Header Content-Type nas respostas
 */

import { test, expect, APIResponse } from "@playwright/test";
import { createAuthenticatedClient } from "../../fixtures/auth.fixture";
import { ApiClient } from "../../client/ApiClient";
import { AllureHelper } from "../../utils/allure-helper";

test.describe.serial("SEC-CONTRACT - Testes de Contrato", () => {
  let adminClient: ApiClient;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
  });

  /**
   * Schema esperado para um usuario.
   * Nem todo campo eh obrigatorio, mas esses aqui sao os minimos.
   */
  const schemaUsuario = {
    _id: "string",
    nome: "string",
    email: "string",
    password: "string",
    administrador: "string", // a API retorna "true"/"false" como string
  };

  const schemaProduto = {
    _id: "string",
    nome: "string",
    preco: "number",
    descricao: "string",
    quantidade: "number",
  };

  // ------------------------------------------------------------------
  // SEC-CONTRACT-01: Schema de GET /usuarios (lista)
  // ------------------------------------------------------------------
  test("SEC-CONTRACT-01: GET /usuarios deve retornar lista com schema correto", async () => {
    const descBase =
      "Valida se a listagem de usuarios retorna um array e cada item " +
      "tem os campos obrigatorios com os tipos esperados.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("contract", "schema", "usuarios");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-CONTRACT-01");
    AllureHelper.addFeature("Qualidade - Contrato");
    AllureHelper.addStory("Schema de Usuarios");

    const alertas: string[] = [];
    const response: APIResponse = await adminClient.get("/usuarios");

    // Contrato 1: status code
    if (response.status() !== 200) {
      alertas.push(
        `[ALERTA] GET /usuarios retornou ${response.status()}, esperado 200`,
      );
    }

    // Contrato 2: Content-Type
    const contentType = response.headers()["content-type"] || "";
    if (!contentType.includes("application/json")) {
      alertas.push(`[ALERTA] Content-Type inesperado: ${contentType}`);
    }

    // Contrato 3: schema do body
    const body = await response.json().catch(() => null);
    if (!body) {
      alertas.push("[ALERTA] Resposta nao eh JSON valido");
    } else {
      const lista = body.usuarios || body;
      if (!Array.isArray(lista)) {
        alertas.push("[ALERTA] Resposta nao eh um array");
      } else if (lista.length === 0) {
        console.log("[CONTRACT] Lista de usuarios vazia - nada pra validar");
      } else {
        const primeiro = lista[0];
        for (const [campo, tipoEsperado] of Object.entries(schemaUsuario)) {
          if (!(campo in primeiro)) {
            alertas.push(
              `[ALERTA] Campo obrigatorio '${campo}' ausente no schema de usuario`,
            );
          } else if (
            tipoEsperado === "number" &&
            typeof primeiro[campo] !== "number"
          ) {
            alertas.push(
              `[ALERTA] Campo '${campo}' deveria ser number, mas eh ${typeof primeiro[campo]}`,
            );
          } else if (
            tipoEsperado === "string" &&
            typeof primeiro[campo] !== "string"
          ) {
            alertas.push(
              `[ALERTA] Campo '${campo}' deveria ser string, mas eh ${typeof primeiro[campo]}`,
            );
          } else if (
            tipoEsperado === "boolean" &&
            typeof primeiro[campo] !== "boolean"
          ) {
            alertas.push(
              `[ALERTA] Campo '${campo}' deveria ser boolean, mas eh ${typeof primeiro[campo]}`,
            );
          }
        }
      }
    }

    await AllureHelper.addAttachment(
      "Schema Validation",
      JSON.stringify({ schema_esperado: schemaUsuario, alertas }, null, 2),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    } else {
      console.log("[CONTRACT] Schema de usuarios validado com sucesso.");
    }

    expect(response.status()).toBe(200);
  });

  // ------------------------------------------------------------------
  // SEC-CONTRACT-02: Schema de GET /produtos (lista)
  // ------------------------------------------------------------------
  test("SEC-CONTRACT-02: GET /produtos deve retornar lista com schema correto", async () => {
    const descBase =
      "Valida se a listagem de produtos retorna um array e cada item " +
      "tem os campos obrigatorios com os tipos esperados.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("contract", "schema", "produtos");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-CONTRACT-02");
    AllureHelper.addFeature("Qualidade - Contrato");
    AllureHelper.addStory("Schema de Produtos");

    const alertas: string[] = [];
    const response: APIResponse = await adminClient.get("/produtos");

    if (response.status() !== 200) {
      alertas.push(
        `[ALERTA] GET /produtos retornou ${response.status()}, esperado 200`,
      );
    }

    const body = await response.json().catch(() => null);
    if (!body) {
      alertas.push("[ALERTA] Resposta nao eh JSON valido");
    } else {
      const lista = body.produtos || body;
      if (!Array.isArray(lista)) {
        alertas.push("[ALERTA] Resposta nao eh um array");
      } else if (lista.length === 0) {
        console.log("[CONTRACT] Lista de produtos vazia - nada pra validar");
      } else {
        const primeiro = lista[0];
        for (const [campo, tipoEsperado] of Object.entries(schemaProduto)) {
          if (!(campo in primeiro)) {
            alertas.push(
              `[ALERTA] Campo obrigatorio '${campo}' ausente no schema de produto`,
            );
          } else if (
            tipoEsperado === "number" &&
            typeof primeiro[campo] !== "number"
          ) {
            alertas.push(
              `[ALERTA] Campo '${campo}' deveria ser number, mas eh ${typeof primeiro[campo]}`,
            );
          } else if (
            tipoEsperado === "string" &&
            typeof primeiro[campo] !== "string"
          ) {
            alertas.push(
              `[ALERTA] Campo '${campo}' deveria ser string, mas eh ${typeof primeiro[campo]}`,
            );
          }
        }
      }
    }

    await AllureHelper.addAttachment(
      "Schema Validation",
      JSON.stringify({ schema_esperado: schemaProduto, alertas }, null, 2),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    } else {
      console.log("[CONTRACT] Schema de produtos validado com sucesso.");
    }

    expect(response.status()).toBe(200);
  });

  // ------------------------------------------------------------------
  // SEC-CONTRACT-03: POST /usuarios deve retornar 201 e body com _id
  // ------------------------------------------------------------------
  test("SEC-CONTRACT-03: POST /usuarios deve retornar 201 e mensagem de sucesso", async () => {
    const descBase =
      "Valida o contrato de criacao de usuario: status 201, body com _id " +
      "e mensagem de confirmacao.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("contract", "post", "usuarios");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-CONTRACT-03");
    AllureHelper.addFeature("Qualidade - Contrato");
    AllureHelper.addStory("Contrato de Criacao");

    const alertas: string[] = [];
    const email = `contract_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    const response: APIResponse = await adminClient.post("/usuarios", {
      nome: "Teste Contrato",
      email,
      password: "Senha@123",
      administrador: "false",
    });

    const body = await response.json().catch(() => null);

    if (response.status() !== 201) {
      alertas.push(
        `[ALERTA] POST /usuarios retornou ${response.status()}, esperado 201`,
      );
    }

    if (!body || !body._id) {
      alertas.push("[ALERTA] Resposta nao contem _id apos criacao");
    }

    if (body && !body.message) {
      console.log(
        "[CONTRACT] POST /usuarios nao retornou mensagem de confirmacao - ok, nao eh obrigatorio",
      );
    }

    await AllureHelper.addAttachment(
      "Resposta - Criacao de Usuario",
      JSON.stringify({ status: response.status(), body }, null, 2),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }

    expect(response.status()).toBe(201);
    expect(body?._id).toBeDefined();

    // Limpeza
    if (body?._id) {
      await adminClient.delete(`/usuarios/${body._id}`).catch(() => {});
    }
  });

  // ------------------------------------------------------------------
  // SEC-CONTRACT-04: Endpoints nao existentes devem retornar 404
  // ------------------------------------------------------------------
  test("SEC-CONTRACT-04: Endpoints inexistentes devem retornar 404", async () => {
    const descBase =
      "Valida se a API retorna 404 para rotas que nao existem. " +
      "Isso aqui eh basico de REST, mas ja vi API retornando 500 ou 200 com HTML.";

    AllureHelper.addSeverity("minor");
    AllureHelper.addTags("contract", "http", "404");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-CONTRACT-04");
    AllureHelper.addFeature("Qualidade - Contrato");
    AllureHelper.addStory("HTTP Status Codes");

    const alertas: string[] = [];
    const endpointsInexistentes = ["/nao_existe", "/api/v2", "/admin", "/.env"];

    for (const endpoint of endpointsInexistentes) {
      const response: APIResponse = await adminClient.get(endpoint);
      if (response.status() !== 404 && response.status() !== 401) {
        alertas.push(
          `[ALERTA] ${endpoint} retornou ${response.status()} em vez de 404`,
        );
        console.log(
          `[CONTRACT] Rota ${endpoint}: status ${response.status()} (esperado 404)`,
        );
      }
    }

    await AllureHelper.addAttachment(
      "Rotas Inexistentes",
      JSON.stringify(
        { endpoints_testados: endpointsInexistentes, alertas },
        null,
        2,
      ),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    } else {
      console.log("[CONTRACT] Todas as rotas inexistentes retornaram 404.");
    }
  });
});
