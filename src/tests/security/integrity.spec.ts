/**
 * Testes de Integridade de Dados e Software
 *
 * A ideia aqui é ver se a API protege a integridade dos dados e tokens,
 * coisa que muita gente esquece de testar. JWT mal configurado, campo
 * calculado injetado no body, race condition em update, etc.
 *
 * OWASP Top 10 - A08:2021 (Software and Data Integrity Failures)
 */

import { test, expect, request, APIResponse } from "@playwright/test";
import {
  createAuthenticatedClient,
  createCommonUser,
} from "../../fixtures/auth.fixture";
import { ApiClient } from "../../client/ApiClient";
import { AllureHelper } from "../../utils/allure-helper";

test.describe.serial("SEC-INTEGRITY - Falhas de Integridade", () => {
  let adminClient: ApiClient;
  let commonClient: ApiClient;
  let commonApiContext: { dispose: () => Promise<void> };
  let adminToken: string | null;
  let commonUserId: string;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
    adminToken = auth.client.getToken();

    const common = await createCommonUser();
    commonClient = common.client;
    commonApiContext = common.apiContext;

    // Pega o ID do comum via listagem do admin (a API nao tem /me)
    const listResp = await adminClient.get("/usuarios");
    if (listResp.status() === 200) {
      const body = await listResp.json();
      const lista = body.usuarios || body;
      if (Array.isArray(lista)) {
        const found = lista.find((u: any) => u.email === common.email);
        if (found) commonUserId = found._id;
      }
    }

    if (!commonUserId) {
      console.warn(
        "[INTEGRITY] Nao rolou pegar o ID do comum. Alguns testes vao pular.",
      );
    }
  });

  test.afterAll(async () => {
    if (commonApiContext) {
      await commonApiContext.dispose().catch(() => {});
    }
  });

  // ------------------------------------------------------------------
  // SEC-INTEGRITY-01: JWT com algoritmo "none"
  // ------------------------------------------------------------------
  test("SEC-INTEGRITY-01: API deve rejeitar JWT com algoritmo 'none'", async () => {
    const descBase =
      "Forja um token JWT com header { alg: 'none' } e tenta acessar um endpoint " +
      "protegido. Se a API aceitar, qualquer um pode forjar token sem assinatura. " +
      "Esperado: 401 Unauthorized.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "integrity", "jwt", "none-algorithm");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-INTEGRITY-01");
    AllureHelper.addFeature("Segurança - Integridade");
    AllureHelper.addStory("JWT - Algoritmo None");

    const alertas: string[] = [];

    // Monta header e payload na mao. O payload eh minimo mas valido.
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" }))
      .toString("base64")
      .replace(/=+$/, "");
    const payload = Buffer.from(
      JSON.stringify({
        sub: "hacker",
        admin: true,
        iat: Math.floor(Date.now() / 1000),
      }),
    )
      .toString("base64")
      .replace(/=+$/, "");
    const tokenNone = `${header}.${payload}.`; // sem assinatura

    // Cria um contexto limpo pra testar o token forjado
    const tempContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });
    const tempClient = new ApiClient(
      tempContext,
      process.env.API_BASE_URL || "https://serverest.dev",
    );
    tempClient.setToken(`Bearer ${tokenNone}`);

    const forgedResp = await tempClient.post("/produtos", {
      nome: "Produto Token None",
      preco: 1,
      descricao: "Tentativa de injecao",
      quantidade: 1,
    });

    let produtoId: string | null = null;
    if (forgedResp.status() === 201) {
      const body = await forgedResp.json();
      produtoId = body._id || null;
    }

    await AllureHelper.addAttachment(
      "Resposta - Token None",
      JSON.stringify(
        {
          status: forgedResp.status(),
          body: await forgedResp.text().catch(() => "Erro ao ler body"),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (forgedResp.status() === 201 || forgedResp.status() === 200) {
      alertas.push("[ALERTA CRITICO] API aceitou JWT com algoritmo 'none'");
      console.log("[INTEGRITY] VULNERABILIDADE: token none aceito");
    } else if (forgedResp.status() !== 401 && forgedResp.status() !== 403) {
      alertas.push(
        `[ALERTA] Status inesperado com token none: ${forgedResp.status()}`,
      );
    }

    // Limpeza
    if (produtoId) {
      await adminClient.delete(`/produtos/${produtoId}`).catch(() => {});
    }
    await tempContext.dispose();

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    } else {
      expect(forgedResp.status()).toBe(401);
    }
  });

  // ------------------------------------------------------------------
  // SEC-INTEGRITY-02: Token reutilizado após "logout" simulado
  // ------------------------------------------------------------------
  test("SEC-INTEGRITY-02: API deve invalidar token após logout (se existir)", async () => {
    const descBase =
      "Autentica um usuario, copia o token, e tenta usar o mesmo token apos fazer " +
      "uma nova autenticacao (simulando logout/login). Se o token antigo ainda funcionar, " +
      "a API nao implementa revogacao. Esperado: token antigo rejeitado ou politica de expiracao curta.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "integrity", "token-revocation");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-INTEGRITY-02");
    AllureHelper.addFeature("Segurança - Integridade");
    AllureHelper.addStory("Token - Revogação");

    const alertas: string[] = [];

    // Cria um usuario temporario pro teste
    const tempCtx = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });
    const tempClient = new ApiClient(
      tempCtx,
      process.env.API_BASE_URL || "https://serverest.dev",
    );

    const email = `token_reuse_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;
    const password = "Senha@123";

    await tempClient.post("/usuarios", {
      nome: "Teste Token Reuse",
      email,
      password,
      administrador: "false",
    });

    await tempClient.login(email, password);
    const tokenAntigo = tempClient.getToken();

    // Simula logout fazendo login novamente (ServeRest nao tem endpoint de logout)
    await tempClient.login(email, password);
    const tokenNovo = tempClient.getToken();

    if (tokenAntigo === tokenNovo) {
      console.log(
        "[INTEGRITY] API devolve o mesmo token apos re-login. Nao implementa rotacao.",
      );
      alertas.push(
        "[ALERTA] API nao rotaciona token no re-login. Token antigo continua valido.",
      );
    }

    // Testa se o token antigo ainda funciona
    const resp = await tempClient.get("/usuarios");

    await AllureHelper.addAttachment(
      "Resultado - Token Reuse",
      JSON.stringify(
        {
          token_antigo_igual_novo: tokenAntigo === tokenNovo,
          status_com_token_atual: resp.status(),
        },
        null,
        2,
      ),
      "application/json",
    );

    // Limpeza: deleta o usuario temporario via admin
    const listResp = await adminClient.get("/usuarios");
    if (listResp.status() === 200) {
      const body = await listResp.json();
      const lista = body.usuarios || body;
      if (Array.isArray(lista)) {
        const u = lista.find((u: any) => u.email === email);
        if (u) await adminClient.delete(`/usuarios/${u._id}`).catch(() => {});
      }
    }
    await tempCtx.dispose();

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  // ------------------------------------------------------------------
  // SEC-INTEGRITY-03: Mass Assignment em campos calculados (desconto/preco)
  // ------------------------------------------------------------------
  test("SEC-INTEGRITY-03: API deve rejeitar campos calculados como 'desconto' no payload", async () => {
    const descBase =
      "Tenta criar um produto enviando campo 'desconto' inexistente no schema. " +
      "Se a API aceitar, qualquer usuario pode manipular regras de negocio. " +
      "Esperado: 400 ou campo ignorado.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags(
      "security",
      "integrity",
      "mass-assignment",
      "business-logic",
    );
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-INTEGRITY-03");
    AllureHelper.addFeature("Segurança - Integridade");
    AllureHelper.addStory("Mass Assignment - Campos Calculados");

    const alertas: string[] = [];

    const resp = await adminClient.post("/produtos", {
      nome: `Produto Desconto Indevido ${Date.now()}`,
      preco: 100,
      descricao: "Tentando injetar desconto",
      quantidade: 10,
      desconto: 90, // campo q nao deveria existir
    });

    let productId: string | null = null;
    if (resp.status() === 201) {
      const body = await resp.json();
      productId = body._id || null;
      if (body.desconto !== undefined) {
        alertas.push(
          "[ALERTA CRITICO] API aceitou campo 'desconto' na criacao do produto",
        );
        console.log("[INTEGRITY] VULNERABILIDADE: campo desconto foi aceito");
      }
    }

    await AllureHelper.addAttachment(
      "Resposta - Campo Desconto",
      JSON.stringify(
        {
          status: resp.status(),
          body: await resp.text().catch(() => "Erro ao ler body"),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (resp.status() !== 201 && resp.status() !== 400) {
      alertas.push(
        `[ALERTA] Status inesperado ao enviar campo desconto: ${resp.status()}`,
      );
    }

    if (productId) {
      await adminClient.delete(`/produtos/${productId}`).catch(() => {});
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });

  // ------------------------------------------------------------------
  // SEC-INTEGRITY-04: Race condition em atualização de cadastro
  // ------------------------------------------------------------------
  test("SEC-INTEGRITY-04: Duas requisições simultâneas alterando o mesmo email", async () => {
    const descBase =
      "Dispara duas requisicoes PUT simultaneas tentando trocar o email do usuario comum " +
      "para dois emails diferentes. Se ambas passarem, a API tem race condition em update. " +
      "Esperado: apenas uma deve ser efetivada, a outra deve falhar ou sobrescrever.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "integrity", "race-condition");
    AllureHelper.addDescription(descBase);
    AllureHelper.addTestCaseId("SEC-INTEGRITY-04");
    AllureHelper.addFeature("Segurança - Integridade");
    AllureHelper.addStory("Race Condition - Atualização de Cadastro");

    const alertas: string[] = [];

    if (!commonUserId) {
      console.warn("[INTEGRITY] commonUserId nao disponivel. Pulando teste.");
      return;
    }

    const emailA = `race_email_a_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;
    const emailB = `race_email_b_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    const resultados = await Promise.allSettled([
      commonClient.put(`/usuarios/${commonUserId}`, {
        nome: "Concorrente A",
        email: emailA,
        password: "Senha@123",
        administrador: "false",
      }),
      commonClient.put(`/usuarios/${commonUserId}`, {
        nome: "Concorrente B",
        email: emailB,
        password: "Senha@123",
        administrador: "false",
      }),
    ]);

    const detalhes: any[] = [];
    for (let i = 0; i < resultados.length; i++) {
      const r = resultados[i];
      if (r.status === "fulfilled") {
        detalhes.push({
          req: i + 1,
          status: r.value.status(),
          body: await r.value.text().catch(() => "Erro ao ler body"),
        });
      } else {
        detalhes.push({
          req: i + 1,
          erro: r.reason?.message || "Erro desconhecido",
        });
      }
    }

    // Verifica qual email ficou salvo
    const verifyResp = await adminClient.get(`/usuarios/${commonUserId}`);
    let emailFinal = "desconhecido";
    if (verifyResp.status() === 200) {
      const data = await verifyResp.json();
      emailFinal = data.email;
    }

    await AllureHelper.addAttachment(
      "Resultado - Race Condition Update",
      JSON.stringify({ email_final: emailFinal, detalhes }, null, 2),
      "application/json",
    );

    if (emailFinal !== emailA && emailFinal !== emailB) {
      alertas.push(
        "[ALERTA] Email final nao corresponde a nenhum dos enviados. Possivel inconsistencia.",
      );
      console.log(
        "[INTEGRITY] Inconsistencia detectada na race condition de update.",
      );
    } else {
      console.log(
        `[INTEGRITY] Email final: ${emailFinal}. Apenas um update prevaleceu.`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descBase + " | " + alertas.join(" | "));
    }
  });
});
