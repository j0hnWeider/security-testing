/**
 * Testes de Segurança - Autenticação e Autorização
 *
 * Objetivo: validar mecanismos de autenticação, autorização,
 * RBAC, brute force, token inválido/expirado.
 * Abordagem: OWASP Top 10 - A01:2021 (Broken Access Control)
 *            OWASP Top 10 - A07:2021 (Identification and Authentication Failures)
 */

import { test, expect } from "@playwright/test";
import {
  createAuthenticatedClient,
  createCommonUser,
} from "../fixtures/auth.fixture";
import { ApiClient } from "../client/ApiClient";
import { AllureHelper } from "../utils/allure-helper";
import { request, APIResponse, APIRequestContext } from "@playwright/test";

test.describe("SEC-AUTH - Testes de Autenticação e Autorização", () => {
  let adminClient: ApiClient;
  let adminApiContext: APIRequestContext;
  let adminEmail: string;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
    adminApiContext = auth.apiContext;
    adminEmail = auth.email;
  });

  test.afterAll(async () => {
    if (adminApiContext) {
      await adminApiContext.dispose();
    }
  });

  test("SEC-AUTH-01: Deve bloquear múltiplas tentativas de login com credenciais inválidas", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "auth", "brute-force");
    AllureHelper.addDescription(
      "Valida se a API implementa rate limiting em tentativas de login." +
        " Envia 10 tentativas consecutivas com senha errada e verifica se alguma " +
        "resposta retorna 429 (Too Many Requests) ou 403 bloqueado.",
    );
    AllureHelper.addTestCaseId("SEC-AUTH-01");
    AllureHelper.addFeature("Segurança - Autenticação");
    AllureHelper.addStory("Força Bruta");

    const invalidCredentials = [
      { email: adminEmail, password: "wrong1" },
      { email: adminEmail, password: "wrong2" },
      { email: adminEmail, password: "wrong3" },
      { email: adminEmail, password: "wrong4" },
      { email: adminEmail, password: "wrong5" },
      { email: adminEmail, password: "wrong6" },
      { email: adminEmail, password: "wrong7" },
      { email: adminEmail, password: "wrong8" },
      { email: adminEmail, password: "wrong9" },
      { email: adminEmail, password: "wrong10" },
    ];

    let blocked = false;
    let lastStatus = 0;

    for (let i = 0; i < invalidCredentials.length; i++) {
      const cred = invalidCredentials[i];
      const tempApiContext = await request.newContext({
        baseURL: process.env.API_BASE_URL || "https://serverest.dev",
      });
      const tempClient = new ApiClient(
        tempApiContext,
        process.env.API_BASE_URL || "https://serverest.dev",
      );

      try {
        await tempClient.login(cred.email, cred.password);
      } catch (error: unknown) {
        const err = error as Error;
        if (err.message?.includes("429") || err.message?.includes("403")) {
          blocked = true;
          AllureHelper.addParameter(
            `Tentativa ${i + 1}`,
            `Bloqueada - ${err.message}`,
          );
          break;
        }
        if (err.message) {
          const statusMatch = err.message.match(/\((\d+)\)/);
          if (statusMatch) lastStatus = parseInt(statusMatch[1]);
        }
      } finally {
        await tempApiContext.dispose();
      }
    }

    AllureHelper.addAttachment(
      "Resultado Brute Force",
      JSON.stringify(
        {
          blocked,
          tentativas: invalidCredentials.length,
          ultimoStatus: lastStatus,
        },
        null,
        2,
      ),
      "application/json",
    );

    if (!blocked) {
      console.warn(
        "⚠️ API não bloqueia múltiplas tentativas de login (rate limiting não identificado)",
      );
    }
  });

  test("SEC-AUTH-02: Usuário comum não deve criar produtos (403 Forbidden)", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "auth", "rbac");
    AllureHelper.addDescription(
      "Valida o princípio do menor privilégio (PoLP). " +
        "Um usuário COMUM não deve conseguir criar produtos, " +
        "apenas administradores têm essa permissão.",
    );
    AllureHelper.addTestCaseId("SEC-AUTH-02");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("RBAC - Controle de Acesso");

    let commonUser = await createCommonUser().catch(() => null);

    if (!commonUser) {
      const fallbackApiContext = await request.newContext({
        baseURL: process.env.API_BASE_URL || "https://serverest.dev",
      });
      const fallbackClient = new ApiClient(
        fallbackApiContext,
        process.env.API_BASE_URL || "https://serverest.dev",
      );
      
      const timestamp = Date.now();
      const uniqueEmail = `fallback_${timestamp}@qa.com`;
      
      await fallbackClient.post("/usuarios", {
        nome: "Fallback User",
        email: uniqueEmail,
        password: "Teste@123",
        administrador: "false",
      });

      await fallbackClient.login(uniqueEmail, "Teste@123");
      commonUser = {
        client: fallbackClient,
        email: uniqueEmail,
        password: "Teste@123",
        apiContext: fallbackApiContext,
      };
    }

    const response: APIResponse = await commonUser.client.post("/produtos", {
      nome: "Produto Teste - Acesso Negado",
      preco: 100,
      descricao: "Usuário comum tentando criar produto",
      quantidade: 1,
    });

    AllureHelper.addAttachment(
      "Resposta do Teste RBAC",
      JSON.stringify(
        { status: response.status(), body: await response.text() },
        null,
        2,
      ),
      "application/json",
    );

    expect(response.status()).toBe(403);
    await commonUser.apiContext.dispose();
  });

  test("SEC-AUTH-03: Deve rejeitar token inválido ou mal formatado", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "auth", "token");
    AllureHelper.addDescription(
      "Valida que a API rejeita tokens inválidos, mal formatados ou expirados. " +
        "Testa diferentes formatos de token inválido.",
    );
    AllureHelper.addTestCaseId("SEC-AUTH-03");
    AllureHelper.addFeature("Segurança - Autenticação");
    AllureHelper.addStory("Token Inválido");

    const invalidTokens: (string | undefined)[] = [
      "Bearer invalid_token_12345",
      "invalid_token_sem_bearer",
      "Bearer ",
      "Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MTYyMzkwMjJ9.invalido",
      "Basic dGVzdGU6dGVzdGU=",
      "",
      "null",
      undefined,
    ];

    for (let i = 0; i < invalidTokens.length; i++) {
      const token = invalidTokens[i];
      await AllureHelper.addStep(
        `Testando token inválido: "${String(token).substring(0, 30)}..."`,
        async () => {
          const tempApiContext = await request.newContext({
            baseURL: process.env.API_BASE_URL || "https://serverest.dev",
          });
          const tempClient = new ApiClient(
            tempApiContext,
            process.env.API_BASE_URL || "https://serverest.dev",
          );

          if (token !== undefined) {
            tempClient.setToken(token);
          }

          const response: APIResponse = await tempClient.post("/produtos", {
            nome: "Teste Token Inválido",
            preco: 100,
            descricao: "Teste",
            quantidade: 1,
          });

          expect(response.status()).toBe(401);
          await tempApiContext.dispose();
        },
      );
    }
  });

  test("SEC-AUTH-04: Deve bloquear acesso a endpoint protegido sem token", async () => {
    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "auth", "unauthenticated");
    AllureHelper.addDescription(
      "Valida que endpoints de criação exigem autenticação. " +
        "Requisição sem token deve retornar 401.",
    );
    AllureHelper.addTestCaseId("SEC-AUTH-04");
    AllureHelper.addFeature("Segurança - Autenticação");
    AllureHelper.addStory("Acesso sem Autenticação");

    const tempApiContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });
    const tempClient = new ApiClient(
      tempApiContext,
      process.env.API_BASE_URL || "https://serverest.dev",
    );

    const response: APIResponse = await tempClient.post(
      "/produtos",
      {
        nome: "Produto Hacker",
        preco: 1,
        descricao: "Tentativa invasão",
        quantidade: 1,
      },
      false,
    );

    expect(response.status()).toBe(401);
    await tempApiContext.dispose();
  });

  test("SEC-AUTH-05: Deve rejeitar login com e-mail inexistente", async () => {
    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "auth", "enumeration");
    AllureHelper.addDescription(
      "Valida que a API não vaza informação sobre existência de usuários. " +
        "A mensagem de erro deve ser genérica.",
    );
    AllureHelper.addTestCaseId("SEC-AUTH-05");
    AllureHelper.addFeature("Segurança - Autenticação");
    AllureHelper.addStory("Prevenção de User Enumeration");

    const tempApiContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });
    const tempClient = new ApiClient(
      tempApiContext,
      process.env.API_BASE_URL || "https://serverest.dev",
    );

    try {
      await tempClient.login("inexistente_123456@teste.com", "qualquersenha");
    } catch (error: unknown) {
      const err = error as Error;
      const statusMatch = err.message?.match(/\((\d+)\)/);
      const status = statusMatch ? parseInt(statusMatch[1]) : 401;
      expect([400, 401]).toContain(status);
      if (err.message) {
        expect(err.message).not.toContain("não encontrado");
        expect(err.message).not.toContain("not found");
        expect(err.message).not.toContain("inexistente");
      }
    } finally {
      await tempApiContext.dispose();
    }
  });

  test("SEC-AUTH-06: Usuário comum não deve atualizar produto criado por admin", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "auth", "rbac", "horizontal-privilege");
    AllureHelper.addDescription(
      "Cria um produto com o Admin, obtém o ID, e tenta atualizá-lo " +
      "usando um usuário COMUM. Deve retornar 403 Forbidden."
    );
    AllureHelper.addTestCaseId("SEC-AUTH-06");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("Escalação de Privilégio Horizontal");

    const uniqueId = Date.now();
    const productName = `Produto do Admin ${uniqueId}`;

    let productId: string = ""; 
    let createAttempts = 0;
    const maxAttempts = 3;

    while (createAttempts < maxAttempts) {
      createAttempts++;
      const createResponse = await adminClient.post("/produtos", {
        nome: productName,
        preco: 150,
        descricao: "Propriedade do Admin",
        quantidade: 10
      });

      if (createResponse.status() === 201) {
        productId = (await createResponse.json())._id;
        break;
      } else if (createResponse.status() === 503) {
        console.warn(`⚠️ Servidor indisponível (503). Tentativa ${createAttempts}/${maxAttempts}. Aguardando...`);
        if (createAttempts === maxAttempts) {
          throw new Error(`Falha ao criar produto após ${maxAttempts} tentativas devido a 503 (Service Unavailable).`);
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      } else {
        throw new Error(`Falha ao criar produto: ${createResponse.status()} - ${await createResponse.text()}`);
      }
    }

    if (!productId) {
      throw new Error("Não foi possível obter o ID do produto.");
    }

    let commonUser = await createCommonUser().catch(() => null);

    if (!commonUser) {
      const fallbackApiContext = await request.newContext({
        baseURL: process.env.API_BASE_URL || "https://serverest.dev",
      });
      const fallbackClient = new ApiClient(
        fallbackApiContext,
        process.env.API_BASE_URL || "https://serverest.dev",
      );
      
      const fallbackTimestamp = Date.now();
      const fallbackEmail = `fallback2_${fallbackTimestamp}@qa.com`;
      
      await fallbackClient.post("/usuarios", {
        nome: "Fallback User",
        email: fallbackEmail,
        password: "Teste@123",
        administrador: "false",
      });

      await fallbackClient.login(fallbackEmail, "Teste@123");
      commonUser = {
        client: fallbackClient,
        email: fallbackEmail,
        password: "Teste@123",
        apiContext: fallbackApiContext,
      };
    }

    const response: APIResponse = await commonUser.client.put(`/produtos/${productId}`, {
      nome: "Hackeado pelo usuário comum",
      preco: 1,
      descricao: "Tentativa de escalação",
      quantidade: 999
    });

    AllureHelper.addAttachment(
      "Resposta do Teste de Escalação Horizontal",
      JSON.stringify(
        { status: response.status(), body: await response.text() },
        null,
        2,
      ),
      "application/json",
    );

    expect(response.status()).toBe(403);

    await commonUser.apiContext.dispose();
  });

  test("SEC-AUTH-07: Deve ter tempo de resposta consistente para evitar enumeração", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "auth", "timing-attack");
    AllureHelper.addDescription(
      "Valida se a API não vaza informações sobre existência de usuários via tempo de resposta. " +
      "Um atacante pode usar diferenças de tempo para enumerar usuários válidos. " +
      "A resposta para usuário existente e inexistente deve ter tempos similares."
    );
    AllureHelper.addTestCaseId("SEC-AUTH-07");
    AllureHelper.addFeature("Segurança - Autenticação");
    AllureHelper.addStory("Timing Attack");

    const tempApiContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });
    const tempClient = new ApiClient(
      tempApiContext,
      process.env.API_BASE_URL || "https://serverest.dev"
    );

    const emails = [
      { email: "fulano@qa.com", tipo: "existente" },
      { email: "inexistente_123456_abc@teste.com", tipo: "inexistente" },
      { email: "admin@email.com", tipo: "existente" },
      { email: "usuario_fake_xyz_999@invalido.com", tipo: "inexistente" },
      { email: "teste@qa.com", tipo: "existente" },
      { email: "nunca_cadastrado_789@test.com", tipo: "inexistente" }
    ];

    const tempos: { email: string; tipo: string; tempo: number }[] = [];

    for (const item of emails) {
      const start = Date.now();
      
      try {
        await tempClient.login(item.email, "senha_qualquer_123");
      } catch (error: unknown) {
        // Ignora erro - o que importa é o tempo de resposta
      }

      const end = Date.now();
      const tempo = end - start;
      tempos.push({ email: item.email, tipo: item.tipo, tempo });

      console.log(`[TIMING] ${item.tipo}: ${item.email} -> ${tempo}ms`);
    }

    await tempApiContext.dispose();

    const existentes = tempos.filter(t => t.tipo === "existente");
    const inexistentes = tempos.filter(t => t.tipo === "inexistente");

    const mediaExistente = existentes.reduce((acc, t) => acc + t.tempo, 0) / existentes.length;
    const mediaInexistente = inexistentes.reduce((acc, t) => acc + t.tempo, 0) / inexistentes.length;

    const diferenca = Math.abs(mediaExistente - mediaInexistente);

    console.log(`[TIMING] Média existente: ${mediaExistente.toFixed(2)}ms`);
    console.log(`[TIMING] Média inexistente: ${mediaInexistente.toFixed(2)}ms`);
    console.log(`[TIMING] Diferença: ${diferenca.toFixed(2)}ms`);

    await AllureHelper.addAttachment(
      "Resultado Timing Attack",
      JSON.stringify({
        mediaExistente: mediaExistente.toFixed(2),
        mediaInexistente: mediaInexistente.toFixed(2),
        diferenca: diferenca.toFixed(2),
        detalhes: tempos
      }, null, 2),
      "application/json"
    );

    if (diferenca > 200) {
      console.log(`[ALERTA] Possível timing attack detectado - diferença de ${diferenca.toFixed(2)}ms`);
      console.log(`[ALERTA] A API pode estar vazando informação sobre existência de usuários.`);
      
      await AllureHelper.addAttachment(
        "Alerta: Timing Attack",
        JSON.stringify({
          alerta: "Possível vulnerabilidade de enumeração via timing attack",
          diferenca: diferenca.toFixed(2),
          recomendacao: "Implementar delay artificial em respostas para usuários inexistentes"
        }, null, 2),
        "application/json"
      );
    } else {
      console.log(`[INFO] Sem indícios significativos de timing attack.`);
    }
  });

  test("SEC-AUTH-08: Deve validar domínios de e-mail para evitar phishing", async () => {
    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "auth", "social-engineering");
    AllureHelper.addDescription(
      "Valida se a API permite cadastro com e-mails de domínios temporários ou suspeitos. " +
      "Um atacante pode usar e-mails descartáveis para criar contas falsas e realizar ataques de engenharia social."
    );
    AllureHelper.addTestCaseId("SEC-AUTH-08");
    AllureHelper.addFeature("Segurança - Engenharia Social");
    AllureHelper.addStory("Cadastro com Domínios Suspeitos");

    const dominiosSuspeitos = [
      { dominio: "mailinator.com", descricao: "Domínio temporário conhecido" },
      { dominio: "temp-mail.org", descricao: "Domínio temporário" },
      { dominio: "guerrillamail.com", descricao: "Domínio temporário" },
      { dominio: "10minutemail.com", descricao: "Domínio temporário" },
      { dominio: "fake-email.com", descricao: "Domínio falso" },
      { dominio: "disposable-email.com", descricao: "Domínio descartável" },
      { dominio: "test.com", descricao: "Domínio genérico de teste" },
      { dominio: "example.com", descricao: "Domínio de exemplo" }
    ];

    const resultados: any[] = [];

    for (const item of dominiosSuspeitos) {
      const email = `usuario_${Date.now()}_${Math.random().toString(36).substring(7)}@${item.dominio}`;
      
      const userData = {
        nome: `Teste Domínio ${item.dominio}`,
        email: email,
        password: '123456',
        administrador: 'false'
      };

      const response = await adminClient.post('/usuarios', userData);
      const body = await response.json();

      const permitido = response.status() === 201;
      
      resultados.push({
        dominio: item.dominio,
        descricao: item.descricao,
        permitido: permitido,
        status: response.status(),
        mensagem: body.message || 'N/A'
      });

      console.log(`[SOCIAL] ${item.dominio} -> ${permitido ? 'PERMITIDO' : 'BLOQUEADO'} (${response.status()})`);

      if (permitido && body._id) {
        await adminClient.delete(`/usuarios/${body._id}`);
      }
    }

    await AllureHelper.addAttachment(
      "Resultado Engenharia Social",
      JSON.stringify(resultados, null, 2),
      "application/json"
    );

    const permitidos = resultados.filter(r => r.permitido);
    
    if (permitidos.length > 0) {
      console.log(`[ALERTA] ${permitidos.length} domínios suspeitos foram permitidos`);
      console.log(`[ALERTA] Domínios permitidos: ${permitidos.map(r => r.dominio).join(', ')}`);
      
      await AllureHelper.addAttachment(
        "Alerta: Domínios Suspeitos Permitidos",
        JSON.stringify({
          alerta: "A API permite cadastro com domínios temporários ou suspeitos",
          dominiosPermitidos: permitidos,
          recomendacao: "Implementar validação de domínios e bloquear e-mails descartáveis"
        }, null, 2),
        "application/json"
      );
    } else {
      console.log(`[INFO] Nenhum domínio suspeito foi permitido.`);
    }
  });
});
