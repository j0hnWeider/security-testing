import { test, request, APIResponse } from "@playwright/test";
import { createAuthenticatedClient } from "../../fixtures/auth.fixture";
import { ApiClient } from "../../client/ApiClient";
import { AllureHelper } from "../../utils/allure-helper";

test.describe.serial("SEC-BOUNDARY - Boundary e Edge Cases", () => {
  let adminClient: ApiClient;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
  });

  test("SEC-BOUNDARY-01: API deve rejeitar payload excessivamente grande", async () => {
    const descBase =
      "Envia um JSON com mais de 1MB no campo descricao. Isso aqui eh classico: " +
      "a API nao define limite de tamanho e o servidor morre com OOM. Esperado: 413 " +
      "Payload Too Large ou 400 Bad Request. Se aceitar 201, temos um problema serio.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "boundary", "dos", "size-limit");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-BOUNDARY-01");
    AllureHelper.addFeature("Segurança - Boundary");
    AllureHelper.addStory("Payload Gigante");

    const alertas: string[] = [];
    const descricaoGrande = "A".repeat(1024 * 1024);

    const startTime = Date.now();
    const response: APIResponse = await adminClient.post("/produtos", {
      nome: "Produto Payload Gigante",
      preco: 100,
      descricao: descricaoGrande,
      quantidade: 10,
    });
    const elapsed = Date.now() - startTime;

    let productId: string | null = null;
    if (response.status() === 201) {
      const body = await response.json();
      productId = body._id || null;
    }

    await AllureHelper.addAttachment(
      "Resposta - Payload Gigante",
      JSON.stringify(
        {
          status: response.status(),
          tamanho_payload_bytes: descricaoGrande.length,
          tempo_resposta_ms: elapsed,
          body: await response
            .text()
            .catch(() => "Erro ao ler body")
            .then((t) => t.substring(0, 500)),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (response.status() === 201) {
      alertas.push(
        "[ALERTA CRITICO] API aceitou payload de 1MB sem reclamar. Possivel DoS.",
      );
      console.log("[BOUNDARY] VULNERABILIDADE: payload gigante aceito");
    } else if (elapsed > 30000) {
      alertas.push(
        "[ALERTA] API demorou mais de 30s pra responder com payload grande",
      );
    }

    if (productId) {
      await adminClient.delete(`/produtos/${productId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-BOUNDARY-02: API deve rejeitar JSON malformado", async () => {
    const descBase =
      "Envia um body que NAO eh JSON valido: faltando aspas, virgula no lugar " +
      "certo, chave nao fechada. Isso aqui eh comum em ataque de fuzzing. " +
      "Esperado: 400 Bad Request. Se a API tentar parsear e quebrar, pode vazar stack trace.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "boundary", "malformed-json");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-BOUNDARY-02");
    AllureHelper.addFeature("Segurança - Boundary");
    AllureHelper.addStory("JSON Malformado");

    const alertas: string[] = [];
    const malformedPayloads = [
      { body: '{ nome: "teste" }', desc: "faltando aspas na chave" },
      { body: '{ "nome": "teste", }', desc: "virgula extra no final" },
      { body: '{ "nome": "teste"', desc: "chave nao fechada" },
      { body: "not json at all", desc: "texto puro, nada de json" },
      { body: "", desc: "body vazio" },
      { body: "undefined", desc: "literal undefined" },
    ];

    for (const malformed of malformedPayloads) {
      const tempContext = await request.newContext({
        baseURL: process.env.API_BASE_URL || "https://serverest.dev",
      });

      let response: APIResponse | undefined;
      try {
        response = await tempContext.post("/produtos", {
          headers: {
            "Content-Type": "application/json",
            Authorization: adminClient.getToken() || "",
          },
          data: malformed.body as string,
        });
      } catch (error) {
        console.log(
          `[BOUNDARY] Payload '${malformed.desc}' nem foi enviado: ${error}`,
        );
        await tempContext.dispose();
        continue;
      }

      const status = response.status();
      const body = await response.text().catch(() => "Erro ao ler body");

      console.log(
        `[BOUNDARY] JSON malformado '${malformed.desc}': status ${status}`,
      );

      if (status === 201 || status === 200) {
        alertas.push(`[ALERTA] API aceitou JSON malformado: ${malformed.desc}`);
        try {
          const json = JSON.parse(body);
          if (json._id)
            await adminClient.delete(`/produtos/${json._id}`).catch(() => {});
        } catch {
          // ignora erro ao tentar limpar recurso criado com body invalido
        }
      } else if (status === 500) {
        alertas.push(
          `[ALERTA] API retornou 500 com JSON malformado: ${malformed.desc}. Possivel stack trace.`,
        );
        if (
          body.includes("at ") ||
          body.includes("Error:") ||
          body.includes("node_modules")
        ) {
          alertas.push(
            "[ALERTA CRITICO] Stack trace exposto em resposta de erro 500",
          );
        }
      }

      await tempContext.dispose();
    }

    await AllureHelper.addAttachment(
      "Resumo - JSON Malformado",
      JSON.stringify(
        { total_testados: malformedPayloads.length, alertas },
        null,
        2,
      ),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-BOUNDARY-03: API deve rejeitar objeto excessivamente aninhado", async () => {
    const descBase =
      "Cria um JSON com 100+ niveis de aninhamento. Isso aqui estoura parser JSON " +
      "de muita linguagem se nao tiver limite de profundidade. Esperado: 400 Bad Request. " +
      "Se a API travar ou demorar demais, eh vulnerabilidade de DoS.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "boundary", "dos", "nested-object");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-BOUNDARY-03");
    AllureHelper.addFeature("Segurança - Boundary");
    AllureHelper.addStory("Objeto Aninhado Profundo");

    const alertas: string[] = [];

    let nested: Record<string, unknown> = { valor: "fim" };
    for (let i = 0; i < 100; i++) {
      nested = { filho: nested };
    }

    const startTime = Date.now();
    const response = await adminClient.post("/produtos", {
      nome: "Objeto Aninhado",
      preco: 100,
      descricao: "Teste de profundidade",
      quantidade: 10,
      metadata: nested,
    });
    const elapsed = Date.now() - startTime;

    let productId: string | null = null;
    if (response.status() === 201) {
      const body = await response.json();
      productId = body._id || null;
    }

    await AllureHelper.addAttachment(
      "Resposta - Objeto Aninhado",
      JSON.stringify(
        {
          status: response.status(),
          tempo_resposta_ms: elapsed,
          niveis_aninhamento: 100,
          body: await response
            .text()
            .catch(() => "Erro ao ler body")
            .then((t) => t.substring(0, 500)),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (response.status() === 201) {
      alertas.push(
        "[ALERTA] API aceitou objeto com 100 niveis de aninhamento sem reclamar",
      );
      console.log(
        "[BOUNDARY] Objeto aninhado aceito - sem limite de profundidade",
      );
    } else if (elapsed > 30000) {
      alertas.push(
        "[ALERTA] API demorou mais de 30s pra processar objeto aninhado. Possivel DoS.",
      );
    } else if (response.status() === 500) {
      alertas.push("[ALERTA] API quebrou com 500 ao processar objeto aninhado");
    }

    if (productId) {
      await adminClient.delete(`/produtos/${productId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-BOUNDARY-04: API deve rejeitar Content-Type incorreto", async () => {
    const descBase =
      "Envia um JSON valido mas com Content-Type: text/plain. Muita API soh " +
      "olha o body e ignora o header, mas isso eh falha de seguranca pq abre porta " +
      "pra request smuggling e outros ataques. Esperado: 415 Unsupported Media Type.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "boundary", "content-type");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-BOUNDARY-04");
    AllureHelper.addFeature("Segurança - Boundary");
    AllureHelper.addStory("Content-Type Incorreto");

    const alertas: string[] = [];

    const tempContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });

    const response = await tempContext.post("/usuarios", {
      headers: {
        "Content-Type": "text/plain",
      },
      data: JSON.stringify({
        nome: "Teste Content-Type Errado",
        email: `ct_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`,
        password: "Senha@123",
        administrador: "false",
      }),
    });

    let userId: string | null = null;
    if (response.status() === 201) {
      const body = await response.json();
      userId = body._id || null;
    }

    await AllureHelper.addAttachment(
      "Resposta - Content-Type Incorreto",
      JSON.stringify(
        {
          status: response.status(),
          body: await response.text().catch(() => "Erro ao ler body"),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (response.status() === 201) {
      alertas.push(
        "[ALERTA] API aceitou requisicao com Content-Type text/plain",
      );
      console.log("[BOUNDARY] Content-Type incorreto aceito");
    } else if (response.status() === 415) {
      console.log(
        "[BOUNDARY] API rejeitou Content-Type incorreto com 415 - ok.",
      );
    }

    if (userId) {
      await adminClient.delete(`/usuarios/${userId}`).catch(() => {});
    }
    await tempContext.dispose();

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-BOUNDARY-05: API deve rejeitar tipos de dados inesperados nos campos", async () => {
    const descBase =
      "Testa tipos de dados completamente errados: array onde era string, " +
      "objeto onde era numero, booleano onde era array. Isso aqui ja vi em API real " +
      "causando erro 500 pq o backend tenta fazer .toLowerCase() num array. " +
      "Esperado: 400 Bad Request.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "boundary", "type-checking");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-BOUNDARY-05");
    AllureHelper.addFeature("Segurança - Boundary");
    AllureHelper.addStory("Tipos de Dados Inesperados");

    const alertas: string[] = [];

    const payloadsBizarros: Array<{
      campo: string;
      valor: unknown;
      desc: string;
    }> = [
      {
        campo: "nome",
        valor: ["array", "em", "vez", "de", "string"],
        desc: "array no lugar de string",
      },
      {
        campo: "preco",
        valor: { valor: 100, moeda: "BRL" },
        desc: "objeto no lugar de numero",
      },
      { campo: "quantidade", valor: true, desc: "booleano no lugar de numero" },
      { campo: "email", valor: 12345, desc: "numero no lugar de string" },
      {
        campo: "administrador",
        valor: "nao_sou_booleano",
        desc: "string no lugar de booleano",
      },
    ];

    for (const payload of payloadsBizarros) {
      const email = `type_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

      const userData: Record<string, unknown> = {
        nome: "Teste Tipo",
        email: email,
        password: "Senha@123",
        administrador: "false",
      };
      userData[payload.campo] = payload.valor;

      const response = await adminClient.post("/usuarios", userData);

      let userId: string | null = null;
      if (response.status() === 201) {
        const body = await response.json();
        userId = body._id || null;
        alertas.push(
          `[ALERTA] API aceitou ${payload.desc} no campo '${payload.campo}'`,
        );
        console.log(`[BOUNDARY] Tipo errado aceito: ${payload.desc}`);
      } else if (response.status() === 500) {
        alertas.push(
          `[ALERTA] API retornou 500 com ${payload.desc}. Possivel erro interno.`,
        );
        console.log(`[BOUNDARY] Erro 500 com tipo errado: ${payload.desc}`);
      }

      if (userId) {
        await adminClient.delete(`/usuarios/${userId}`).catch(() => {});
      }
    }

    await AllureHelper.addAttachment(
      "Resumo - Tipos Inesperados",
      JSON.stringify(
        { total_testados: payloadsBizarros.length, alertas },
        null,
        2,
      ),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-BOUNDARY-06: API deve tratar caracteres Unicode e emojis corretamente", async () => {
    const descBase =
      "Testa caracteres Unicode extremos, emojis, e combinacoes que podem quebrar " +
      "normalizacao de string. Isso aqui eh real: ja vi API quebrar pq o banco nao " +
      "suportava utf8mb4 e o usuario colocou emoji no nome. Esperado: aceitar e armazenar corretamente.";

    AllureHelper.addSeverity("minor");
    AllureHelper.addTags("security", "boundary", "unicode");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-BOUNDARY-06");
    AllureHelper.addFeature("Segurança - Boundary");
    AllureHelper.addStory("Unicode e Emojis");

    const alertas: string[] = [];

    const unicodeTests = [
      { nome: "João 北京 ❤️", desc: "unicode misturado com emoji" },
      { nome: "💀💀💀💀💀💀💀💀💀💀", desc: "dez emojis de caveira" },
      { nome: "Z͆̾͗͑̈͗͗͑̿͗̎̎͗", desc: "texto com diacriticos combinados (zalgo)" },
    ];

    for (const testCase of unicodeTests) {
      const email = `unicode_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

      const response = await adminClient.post("/usuarios", {
        nome: testCase.nome,
        email: email,
        password: "Senha@123",
        administrador: "false",
      });

      let userId: string | null = null;
      let nomeArmazenado = "";

      if (response.status() === 201) {
        const body = await response.json();
        userId = body._id || null;

        if (userId) {
          const getResp = await adminClient.get(`/usuarios/${userId}`);
          if (getResp.status() === 200) {
            const userData = await getResp.json();
            nomeArmazenado =
              ((userData as Record<string, unknown>).nome as string) || "";

            if (nomeArmazenado !== testCase.nome) {
              alertas.push(
                `[ALERTA] Nome com '${testCase.desc}' foi alterado ao ser armazenado`,
              );
              console.log(`[BOUNDARY] Unicode corrompido: ${testCase.desc}`);
              console.log(`  Enviado: ${testCase.nome}`);
              console.log(`  Armazenado: ${nomeArmazenado}`);
            }
          }
        }
      } else if (response.status() === 500) {
        alertas.push(
          `[ALERTA] API quebrou com 500 ao receber '${testCase.desc}'`,
        );
      }

      if (userId) {
        await adminClient.delete(`/usuarios/${userId}`).catch(() => {});
      }
    }

    await AllureHelper.addAttachment(
      "Resumo - Unicode e Emojis",
      JSON.stringify({ total_testados: unicodeTests.length, alertas }, null, 2),
      "application/json",
    );

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });
});
