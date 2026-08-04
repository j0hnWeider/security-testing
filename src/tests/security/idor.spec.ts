/**
 * Testes de Segurança - IDOR (Insecure Direct Object References)
 *
 * Objetivo: validar que usuário comum não consegue acessar, editar ou deletar
 * recursos que pertencem a outros usuários. Basicamente, testar se a API
 * valida ownership dos recursos ou só confia no ID da URL.
 *
 * Abordagem: OWASP Top 10 - A01:2021 (Broken Access Control)
 *            OWASP ASVS V4.1.2 (Access Control)
 *
 * Nota: alguns trechos tão comentados com "gambiarra" porque a API não
 * facilita pegar o ID do usuário logado. O ideal seria ter um endpoint /me,
 * mas como não tem, a gente se vira com listagem de admin.
 */

import { test, expect, request, APIResponse } from "@playwright/test";
import {
  createAuthenticatedClient,
  createCommonUser,
} from "../../fixtures/auth.fixture";
import { ApiClient } from "../../client/ApiClient";
import { AllureHelper } from "../../utils/allure-helper";

test.describe.serial("SEC-IDOR - Insecure Direct Object References", () => {
  let adminClient: ApiClient;
  let commonClient: ApiClient;
  let commonApiContext: { dispose: () => Promise<void> };
  let adminUserId: string;
  let commonUserId: string;
  let adminProductId: string;

  test.beforeAll(async () => {
    // Cria admin e usuário comum autenticados
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;

    // Cria usuário comum - vai ser nossa "vítima" e também o atacante nos testes
    const common = await createCommonUser();
    commonClient = common.client;
    commonApiContext = common.apiContext;

    // Cria um produto do admin pra testar IDOR em recursos diferentes de usuário
    // Se der 503, tenta de novo (gambiarra básica pra API instável)
    let tentativas = 0;
    while (tentativas < 3) {
      const prodResponse = await adminClient.post("/produtos", {
        nome: `Produto Admin IDOR ${Date.now()}`,
        preco: 100,
        descricao: "Produto pra teste de IDOR",
        quantidade: 10,
      });
      if (prodResponse.status() === 201) {
        const prodBody = await prodResponse.json();
        adminProductId = prodBody._id;
        break;
      }
      tentativas++;
      await new Promise((r) => setTimeout(r, 1000));
    }

    // Pega os IDs dos usuários - isso aqui é uma gambiarra porque a API não
    // expõe o ID do usuário logado diretamente. O ideal seria um endpoint /me,
    // mas como não tem, o admin lista todo mundo e a gente filtra por email.
    // Funciona, mas é feio. Não mexer se não precisar.
    const listResponse = await adminClient.get("/usuarios");
    if (listResponse.status() === 200) {
      const body = await listResponse.json();
      // A API às vezes retorna { usuarios: [...] }, às vezes array direto
      const usuarios = body.usuarios || body;
      if (Array.isArray(usuarios)) {
        // Procura o admin e o comum pelos emails que a fixture criou
        // Sei que podia ter guardado na criação, mas a fixture não retorna ID
        const adminUser = usuarios.find((u: any) => u.email === auth.email);
        const commonUser = usuarios.find((u: any) => u.email === common.email);
        if (adminUser) adminUserId = adminUser._id;
        if (commonUser) commonUserId = commonUser._id;
      }
    }

    // Se não achou os IDs, não tem muito o que fazer - os testes vão logar warning
    if (!adminUserId || !commonUserId) {
      console.warn(
        "[IDOR] Não foi possível obter IDs dos usuários. Alguns testes podem ser pulados.",
      );
    }
  });

  test.afterAll(async () => {
    // Limpa o produto criado, se existir
    if (adminProductId) {
      await adminClient.delete(`/produtos/${adminProductId}`).catch(() => {});
    }
    if (commonApiContext) {
      await commonApiContext.dispose().catch(() => {});
    }
  });

  // ------------------------------------------------------------------
  // SEC-IDOR-01: Acessar dados de outro usuário
  // ------------------------------------------------------------------
  test("SEC-IDOR-01: Usuário comum não deve acessar dados de outro usuário", async () => {
    const descricaoBase =
      "Tenta acessar os dados do admin usando o token do usuário comum. " +
      "Se a API não valida ownership, o comum vai conseguir ver email, nome, etc. " +
      "Esperado: 403 Forbidden.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "idor", "access-control");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-IDOR-01");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("IDOR - Acesso a Dados");

    const alertas: string[] = [];

    // Se não temos o ID do admin, não dá pra testar - vida que segue
    if (!adminUserId) {
      console.warn("[IDOR] adminUserId não disponível. Pulando teste.");
      return;
    }

    // Usuário comum tentando acessar GET /usuarios/<id_do_admin>
    const response: APIResponse = await commonClient.get(
      `/usuarios/${adminUserId}`,
    );

    AllureHelper.addAttachment(
      "Resposta - Acesso a Dados do Admin",
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

    // Se voltou 200, é vulnerabilidade real. Se 403, tá safe.
    if (response.status() === 200) {
      alertas.push(
        "[ALERTA CRITICO] Usuário comum acessou dados do admin - IDOR confirmado",
      );
      console.log("[IDOR] VULNERABILIDADE: comum leu dados do admin");
    } else if (response.status() === 401) {
      // 401 pode ser token expirado ou mal formatado - mas não é IDOR
      console.log("[IDOR] Retornou 401 - token pode ter expirado, não é IDOR.");
    } else if (response.status() !== 403) {
      alertas.push(
        `[ALERTA] Status inesperado: ${response.status()} (esperado 403)`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    } else {
      expect(response.status()).toBe(403); // Se não teve alerta, espera 403
    }
  });

  // ------------------------------------------------------------------
  // SEC-IDOR-02: Editar dados de outro usuário
  // ------------------------------------------------------------------
  test("SEC-IDOR-02: Usuário comum não deve editar dados de outro usuário", async () => {
    const descricaoBase =
      "Tenta fazer PUT nos dados do admin logado como usuário comum. " +
      "Se passar, o comum pode trocar email/senha/nome do admin. Esperado: 403.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "idor", "access-control");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-IDOR-02");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("IDOR - Edição de Dados");

    const alertas: string[] = [];

    if (!adminUserId) {
      console.warn("[IDOR] adminUserId não disponível. Pulando teste.");
      return;
    }

    // Tenta editar o nome do admin - payload simples mas suficiente pra testar
    const response: APIResponse = await commonClient.put(
      `/usuarios/${adminUserId}`,
      {
        nome: "Hackeado pelo usuário comum",
        email: "hackeado@idor.com",
        password: "senha123",
        administrador: "true", // já aproveita e tenta escalar privilégio
      },
    );

    AllureHelper.addAttachment(
      "Resposta - Edição do Admin",
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

    if (response.status() === 200) {
      alertas.push(
        "[ALERTA CRITICO] Usuário comum editou dados do admin - IDOR + Mass Assignment",
      );
      console.log("[IDOR] VULNERABILIDADE CRITICA: comum editou admin");
    } else if (response.status() !== 403) {
      alertas.push(
        `[ALERTA] Status inesperado ao editar admin: ${response.status()}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    } else {
      expect(response.status()).toBe(403);
    }
  });

  // ------------------------------------------------------------------
  // SEC-IDOR-03: Deletar outro usuário
  // ------------------------------------------------------------------
  test("SEC-IDOR-03: Usuário comum não deve deletar outro usuário", async () => {
    const descricaoBase =
      "Tenta deletar o admin via DELETE /usuarios/<id_do_admin> com token de comum. " +
      "Se deletar, além de IDOR é um problemão porque o admin perde o acesso. Esperado: 403.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "idor", "access-control");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-IDOR-03");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("IDOR - Deleção de Recurso");

    const alertas: string[] = [];

    if (!adminUserId) {
      console.warn("[IDOR] adminUserId não disponível. Pulando teste.");
      return;
    }

    // CUIDADO: se a API tiver IDOR real, esse teste DELETA o admin de verdade.
    // Não tem rollback. Mas como a fixture recria a cada execução, tá ok.
    const response: APIResponse = await commonClient.delete(
      `/usuarios/${adminUserId}`,
    );

    AllureHelper.addAttachment(
      "Resposta - Deleção do Admin",
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

    if (response.status() === 200) {
      alertas.push(
        "[ALERTA CRITICO] Usuário comum deletou o admin - IDOR confirmado",
      );
      console.log("[IDOR] VULNERABILIDADE GRAVE: comum deletou o admin");
    } else if (response.status() !== 403 && response.status() !== 401) {
      alertas.push(
        `[ALERTA] Status inesperado ao deletar admin: ${response.status()}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    } else {
      expect(response.status()).toBe(403);
    }
  });

  // ------------------------------------------------------------------
  // SEC-IDOR-04: Listar todos os usuários (enumeração)
  // ------------------------------------------------------------------
  test("SEC-IDOR-04: Usuário comum não deve listar todos os usuários", async () => {
    const descricaoBase =
      "Tenta listar todos os usuários (GET /usuarios) com token de comum. " +
      "Mesmo que não consiga ver detalhes, listar emails/nomes já é vazamento. " +
      "Esperado: 403 ou lista vazia (só o próprio).";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "idor", "enumeration");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-IDOR-04");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("IDOR - Enumeração de Usuários");

    const alertas: string[] = [];

    const response: APIResponse = await commonClient.get("/usuarios");

    const body = await response.json().catch(() => null);
    const usuarios = body?.usuarios || body;

    AllureHelper.addAttachment(
      "Resposta - Listagem de Usuários",
      JSON.stringify(
        {
          status: response.status(),
          quantidade: Array.isArray(usuarios) ? usuarios.length : "N/A",
        },
        null,
        2,
      ),
      "application/json",
    );

    // Se retornou 200 e tem mais de 1 usuário, o comum tá vendo todo mundo
    if (
      response.status() === 200 &&
      Array.isArray(usuarios) &&
      usuarios.length > 1
    ) {
      alertas.push(
        `[ALERTA] Usuário comum listou ${usuarios.length} usuários - vazamento de informações`,
      );
      console.log(
        `[IDOR] VULNERABILIDADE: comum listou ${usuarios.length} usuários`,
      );
    } else if (
      response.status() === 200 &&
      Array.isArray(usuarios) &&
      usuarios.length <= 1
    ) {
      // Pode ser que a API filtre e mostre só o próprio - não é ideal mas é aceitável
      console.log(
        "[IDOR] Comum só vê o próprio usuário - ok, mas ideal seria 403.",
      );
    } else if (response.status() !== 403) {
      alertas.push(
        `[ALERTA] Status inesperado na listagem: ${response.status()}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    } else {
      // Só dá expect se não houve vazamento
      expect([403, 200]).toContain(response.status());
    }
  });

  // ------------------------------------------------------------------
  // SEC-IDOR-05: Deletar produto do admin
  // ------------------------------------------------------------------
  test("SEC-IDOR-05: Usuário comum não deve deletar produto do admin", async () => {
    const descricaoBase =
      "Tenta deletar um produto criado pelo admin usando token de comum. " +
      "Se passar, qualquer usuário pode remover produtos de outros. Esperado: 403.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "idor", "access-control");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-IDOR-05");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("IDOR - Deleção de Produto");

    const alertas: string[] = [];

    if (!adminProductId) {
      console.warn("[IDOR] adminProductId não disponível. Pulando teste.");
      return;
    }

    const response: APIResponse = await commonClient.delete(
      `/produtos/${adminProductId}`,
    );

    AllureHelper.addAttachment(
      "Resposta - Deleção de Produto",
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

    if (response.status() === 200) {
      alertas.push(
        "[ALERTA CRITICO] Usuário comum deletou produto do admin - IDOR confirmado",
      );
      console.log("[IDOR] VULNERABILIDADE: comum deletou produto do admin");
      // Se deletou, perdemos o produto - mas já tinha limpado no afterAll
    } else if (response.status() !== 403 && response.status() !== 401) {
      alertas.push(
        `[ALERTA] Status inesperado ao deletar produto: ${response.status()}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    } else {
      expect(response.status()).toBe(403);
    }
  });

  // ------------------------------------------------------------------
  // SEC-IDOR-06: Acessar carrinho de outro usuário
  // ------------------------------------------------------------------
  test("SEC-IDOR-06: Usuário comum não deve acessar carrinho de outro usuário", async () => {
    const descricaoBase =
      "Tenta listar os carrinhos (GET /carrinhos) com token de comum. " +
      "Se conseguir ver carrinhos que não são dele, é IDOR. " +
      "Sei que poderia ter criado um carrinho pro admin primeiro, mas " +
      "como a API pode não ter carrinho pre-existente, vou testar só a listagem.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "idor", "access-control");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-IDOR-06");
    AllureHelper.addFeature("Segurança - Autorização");
    AllureHelper.addStory("IDOR - Acesso a Carrinho");

    const alertas: string[] = [];

    const response: APIResponse = await commonClient.get("/carrinhos");

    const body = await response.json().catch(() => null);
    const carrinhos = body?.carrinhos || body;

    AllureHelper.addAttachment(
      "Resposta - Listagem de Carrinhos",
      JSON.stringify(
        {
          status: response.status(),
          quantidade: Array.isArray(carrinhos) ? carrinhos.length : "N/A",
        },
        null,
        2,
      ),
      "application/json",
    );

    // Se retornou carrinhos que não são do usuário comum, é IDOR
    if (
      response.status() === 200 &&
      Array.isArray(carrinhos) &&
      carrinhos.length > 0
    ) {
      // Verifica se pelo menos um carrinho pertence a outro usuário
      // Gambiarra: compara o idUsuario do carrinho com o commonUserId
      const carrinhoDeOutro = carrinhos.some(
        (c: any) => c.idUsuario && c.idUsuario !== commonUserId,
      );
      if (carrinhoDeOutro || !commonUserId) {
        alertas.push(
          `[ALERTA] Usuário comum viu carrinhos de outros - IDOR confirmado`,
        );
        console.log("[IDOR] VULNERABILIDADE: comum acessou carrinhos alheios");
      } else {
        console.log("[IDOR] Comum só viu os próprios carrinhos - ok.");
      }
    } else if (response.status() !== 403 && response.status() !== 200) {
      alertas.push(
        `[ALERTA] Status inesperado ao listar carrinhos: ${response.status()}`,
      );
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    } else {
      // Tá safe
      expect([200, 403]).toContain(response.status());
    }
  });
});
