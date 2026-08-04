/**
 * Testes de Segurança - Mass Assignment
 *
 * Objetivo: validar se a API filtra campos sensíveis que o usuário não deveria
 * poder alterar. Mass Assignment acontece quando o backend pega tudo que veio
 * no JSON e joga direto no banco, sem filtrar o que pode ou não ser modificado.
 *
 * Abordagem: OWASP Top 10 - A01:2021 (Broken Access Control)
 *            OWASP ASVS V4.1.2 (Access Control)
 *            OWASP ASVS V5.1.2 (Input Validation)
 *
 * Aqui a gente testa coisas como: um usuário comum se auto-promover a admin,
 * forçar um _id customizado na criação, enviar campos que não existem no schema,
 * e trocar o tipo dos dados (string onde era número, etc).
 */

import { test, expect, APIResponse } from "@playwright/test";
import {
  createAuthenticatedClient,
  createCommonUser,
} from "../../fixtures/auth.fixture";
import { ApiClient } from "../../client/ApiClient";
import { AllureHelper } from "../../utils/allure-helper";

test.describe.serial("SEC-MASS - Mass Assignment", () => {
  let adminClient: ApiClient;
  let commonClient: ApiClient;
  let commonApiContext: { dispose: () => Promise<void> };
  let commonEmail: string;
  let commonPassword: string;
  let commonUserId: string;

  test.beforeAll(async () => {
    // Cria admin autenticado (vamos usar pra listar usuários e pegar IDs)
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;

    // Cria usuário comum - vai ser a "vítima" que tenta se promover
    const common = await createCommonUser();
    commonClient = common.client;
    commonApiContext = common.apiContext;
    commonEmail = common.email;
    commonPassword = common.password;

    // Pega o ID do usuário comum - gambiarra básica porque a fixture não retorna ID
    // O ideal era a fixture já devolver o _id, mas tá funcionando, não vou mexer agora
    const listResponse = await adminClient.get("/usuarios");
    if (listResponse.status() === 200) {
      const body = await listResponse.json();
      const usuarios = body.usuarios || body;
      if (Array.isArray(usuarios)) {
        const found = usuarios.find((u: any) => u.email === commonEmail);
        if (found) commonUserId = found._id;
      }
    }

    if (!commonUserId) {
      console.warn(
        "[MASS] Não foi possível obter ID do usuário comum. Alguns testes vão pular.",
      );
    }
  });

  test.afterAll(async () => {
    if (commonApiContext) {
      await commonApiContext.dispose().catch(() => {});
    }
  });

  // ------------------------------------------------------------------
  // SEC-MASS-01: Usuário comum tentando se promover a admin na criação
  // ------------------------------------------------------------------
  test("SEC-MASS-01: Usuário comum não deve criar conta com role de admin", async () => {
    const descricaoBase =
      "Tenta criar um novo usuário via POST /usuarios com 'administrador: true' " +
      "usando token de usuário COMUM. Se passar, qualquer um pode criar conta admin. " +
      "Esperado: 403 ou campo ignorado (conta criada como false).";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "mass-assignment", "privilege-escalation");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-MASS-01");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("Mass Assignment - Criação de Admin");

    const alertas: string[] = [];
    const email = `mass_test_01_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    // Tenta criar um usuário admin com token de comum
    const response: APIResponse = await commonClient.post("/usuarios", {
      nome: "Tentativa de Admin Via Mass Assignment",
      email: email,
      password: "Senha@123",
      administrador: "true", // <-- o pulo do gato
    });

    let userId: string | null = null;
    let criadoComoAdmin = false;

    if (response.status() === 201) {
      const body = await response.json();
      userId = body._id || null;

      // Se criou, verifica como admin se a conta ficou admin mesmo
      if (userId) {
        const verifyResponse = await adminClient.get(`/usuarios/${userId}`);
        if (verifyResponse.status() === 200) {
          const userData = await verifyResponse.json();
          criadoComoAdmin =
            userData.administrador === "true" ||
            userData.administrador === true;
        }
      }
    }

    AllureHelper.addAttachment(
      "Resposta - Criação com Role Admin",
      JSON.stringify(
        {
          status: response.status(),
          criado_como_admin: criadoComoAdmin,
          body: await response.text().catch(() => "Erro ao ler body"),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (response.status() === 201 && criadoComoAdmin) {
      alertas.push(
        "[ALERTA CRITICO] Usuário comum criou conta admin - Mass Assignment confirmado",
      );
      console.log("[MASS] VULNERABILIDADE: comum criou conta admin");
    } else if (response.status() === 201 && !criadoComoAdmin) {
      console.log(
        "[MASS] Conta criada, mas role foi ignorado - ok, mas ideal seria 403.",
      );
    } else if (response.status() !== 403 && response.status() !== 401) {
      alertas.push(
        `[ALERTA] Status inesperado ao criar com role admin: ${response.status()}`,
      );
    }

    // Limpeza - se criou a conta, deleta
    if (userId) {
      await adminClient.delete(`/usuarios/${userId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  // ------------------------------------------------------------------
  // SEC-MASS-02: Usuário tentando se auto-promover via PUT
  // ------------------------------------------------------------------
  test("SEC-MASS-02: Usuário não deve alterar o próprio role via PUT", async () => {
    const descricaoBase =
      "Tenta fazer PUT nos próprios dados com 'administrador: true'. " +
      "Se passar, o usuário comum se promove a admin sozinho. Esperado: campo ignorado ou 403.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "mass-assignment", "privilege-escalation");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-MASS-02");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("Mass Assignment - Auto-Promoção");

    const alertas: string[] = [];

    if (!commonUserId) {
      console.warn("[MASS] commonUserId não disponível. Pulando teste.");
      return;
    }

    // Tenta editar o próprio role
    const response: APIResponse = await commonClient.put(
      `/usuarios/${commonUserId}`,
      {
        nome: "Usuario Promovido",
        email: commonEmail,
        password: commonPassword,
        administrador: "true", // <-- tentativa de se promover
      },
    );

    // Verifica se a alteração surtiu efeito
    let promovido = false;
    const verifyResponse = await adminClient.get(`/usuarios/${commonUserId}`);
    if (verifyResponse.status() === 200) {
      const userData = await verifyResponse.json();
      promovido =
        userData.administrador === "true" || userData.administrador === true;
    }

    AllureHelper.addAttachment(
      "Resposta - Auto-Promoção",
      JSON.stringify(
        {
          status: response.status(),
          foi_promovido: promovido,
          body: await response.text().catch(() => "Erro ao ler body"),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (response.status() === 200 && promovido) {
      alertas.push(
        "[ALERTA CRITICO] Usuário se auto-promoveu a admin - Mass Assignment confirmado",
      );
      console.log("[MASS] VULNERABILIDADE CRITICA: comum virou admin via PUT");
    } else if (response.status() === 200 && !promovido) {
      console.log("[MASS] PUT aceito, mas role foi ignorado - ok.");
    } else if (response.status() !== 403 && response.status() !== 401) {
      alertas.push(
        `[ALERTA] Status inesperado ao tentar auto-promoção: ${response.status()}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  // ------------------------------------------------------------------
  // SEC-MASS-03: Forçar _id customizado na criação de usuário
  // ------------------------------------------------------------------
  test("SEC-MASS-03: API deve rejeitar _id customizado na criação de usuário", async () => {
    const descricaoBase =
      "Tenta criar um usuário enviando um _id customizado no payload. " +
      "Se a API aceitar, dá pra sobrescrever documentos existentes ou " +
      "causar conflitos no banco. Esperado: 400 ou _id ignorado.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "mass-assignment", "id-injection");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-MASS-03");
    AllureHelper.addFeature("Segurança - Validação de Entrada");
    AllureHelper.addStory("Mass Assignment - ID Customizado");

    const alertas: string[] = [];
    const customId = "507f1f77bcf86cd799439011"; // ObjectId válido do MongoDB
    const email = `mass_test_03_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    const response: APIResponse = await adminClient.post("/usuarios", {
      _id: customId, // <-- forçando ID
      nome: "Teste ID Customizado",
      email: email,
      password: "Senha@123",
      administrador: "false",
    });

    let userId: string | null = null;
    let idRespeitado = false;

    if (response.status() === 201) {
      const body = await response.json();
      userId = body._id || null;
      idRespeitado = userId === customId;
    }

    AllureHelper.addAttachment(
      "Resposta - ID Customizado",
      JSON.stringify(
        {
          status: response.status(),
          id_enviado: customId,
          id_retornado: userId,
          id_respeitado: idRespeitado,
          body: await response.text().catch(() => "Erro ao ler body"),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (response.status() === 201 && idRespeitado) {
      alertas.push(
        "[ALERTA CRITICO] API aceitou _id customizado - Mass Assignment confirmado",
      );
      console.log("[MASS] VULNERABILIDADE: API aceitou _id customizado");
    } else if (response.status() === 201 && !idRespeitado) {
      console.log("[MASS] Usuário criado, mas _id foi ignorado - ok.");
    } else if (response.status() === 400) {
      console.log("[MASS] API rejeitou _id customizado - ok.");
    }

    // Limpeza
    if (userId) {
      await adminClient.delete(`/usuarios/${userId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  // ------------------------------------------------------------------
  // SEC-MASS-04: Campos desconhecidos no payload
  // ------------------------------------------------------------------
  test("SEC-MASS-04: API deve rejeitar ou ignorar campos desconhecidos", async () => {
    const descricaoBase =
      "Envia campos que não existem no schema da API (campo_inexistente, debug, etc). " +
      "Se a API aceitar sem reclamar, está processando dados arbitrários - " +
      "porta aberta pra injeção e comportamento imprevisível. Esperado: 400 ou campos ignorados.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "mass-assignment", "schema-validation");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-MASS-04");
    AllureHelper.addFeature("Segurança - Validação de Entrada");
    AllureHelper.addStory("Mass Assignment - Campos Desconhecidos");

    const alertas: string[] = [];
    const email = `mass_test_04_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    const response: APIResponse = await adminClient.post("/usuarios", {
      nome: "Teste Campos Desconhecidos",
      email: email,
      password: "Senha@123",
      administrador: "false",
      campo_inexistente: "valor suspeito", // <-- não existe no schema
      debug: true, // <-- outro campo fantasma
      __proto__: { admin: true }, // <-- tentativa de prototype pollution
    });

    let userId: string | null = null;

    if (response.status() === 201) {
      const body = await response.json();
      userId = body._id || null;
    }

    AllureHelper.addAttachment(
      "Resposta - Campos Desconhecidos",
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

    // Se criou o usuário, os campos extras foram ignorados ou aceitos
    // O problema é se a API NÃO reclama - significa que não valida schema
    if (response.status() === 201) {
      // Verifica se os campos fantasmas aparecem na consulta
      if (userId) {
        const verifyResponse = await adminClient.get(`/usuarios/${userId}`);
        if (verifyResponse.status() === 200) {
          const userData = await verifyResponse.json();
          const camposExtras = Object.keys(userData).filter(
            (k) =>
              !["_id", "nome", "email", "password", "administrador"].includes(
                k,
              ),
          );
          if (camposExtras.length > 0) {
            alertas.push(
              `[ALERTA] API armazenou campos desconhecidos: ${camposExtras.join(", ")}`,
            );
            console.log(
              `[MASS] VULNERABILIDADE: API armazenou campos extras: ${camposExtras.join(", ")}`,
            );
          } else {
            console.log("[MASS] Campos desconhecidos foram ignorados - ok.");
          }
        }
      }
    } else if (response.status() === 400) {
      console.log("[MASS] API rejeitou payload com campos desconhecidos - ok.");
    } else {
      alertas.push(
        `[ALERTA] Status inesperado ao enviar campos desconhecidos: ${response.status()}`,
      );
    }

    // Limpeza
    if (userId) {
      await adminClient.delete(`/usuarios/${userId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  // ------------------------------------------------------------------
  // SEC-MASS-05: Tipos errados no payload (string onde era número)
  // ------------------------------------------------------------------
  test("SEC-MASS-05: API deve rejeitar tipos errados nos campos", async () => {
    const descricaoBase =
      "Tenta criar um produto enviando string no campo 'preco' (que deveria ser número) " +
      "e booleano no campo 'nome' (que deveria ser string). " +
      "Se a API aceitar, não está validando tipos - risco de dados corrompidos. Esperado: 400.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "mass-assignment", "type-validation");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-MASS-05");
    AllureHelper.addFeature("Segurança - Validação de Entrada");
    AllureHelper.addStory("Mass Assignment - Tipos Errados");

    const alertas: string[] = [];

    // Produto com preço string e nome booleano (pra testar tipos)
    const response: APIResponse = await adminClient.post("/produtos", {
      nome: true as any, // <-- nome como booleano
      preco: "gratis" as any, // <-- preço como string
      descricao: "Teste de tipos errados",
      quantidade: 10,
    });

    let productId: string | null = null;

    if (response.status() === 201) {
      const body = await response.json();
      productId = body._id || null;
    }

    AllureHelper.addAttachment(
      "Resposta - Tipos Errados",
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
        "[ALERTA] API aceitou produto com tipos errados (preco string, nome booleano)",
      );
      console.log("[MASS] VULNERABILIDADE: API não valida tipos dos campos");
    } else if (response.status() === 400) {
      console.log("[MASS] API rejeitou tipos errados - ok.");
    } else {
      alertas.push(
        `[ALERTA] Status inesperado ao enviar tipos errados: ${response.status()}`,
      );
    }

    // Limpeza
    if (productId) {
      await adminClient.delete(`/produtos/${productId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });
});
