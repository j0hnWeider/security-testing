/**
 * Testes de Segurança - Race Condition
 *
 * Objetivo: validar se a API trata corretamente operações concorrentes
 * que podem causar inconsistência de dados, como comprar o mesmo produto
 * várias vezes quando o estoque é limitado.
 *
 * Abordagem: OWASP Top 10 - A04:2021 (Insecure Design)
 *            OWASP ASVS V4.1.2 (Access Control)
 *            OWASP ASVS V5.1.2 (Input Validation)
 *
 * Contexto: Em APIs de e-commerce, race condition em compras é critica.
 * Se dois usuários compram o ultimo item ao mesmo tempo, só um deveria
 * conseguir. Se ambos conseguem, o estoque fica negativo e o negócio
 * toma prejuízo (ou vende coisa que não tem).
 *
 * Aqui a gente cria um produto com estoque limitado e dispara várias
 * requisições simultâneas pra comprar. Se mais de uma passar, temos
 * uma vulnerabilidade real de negócio.
 */

import { test, expect, request, APIResponse } from "@playwright/test";
import {
  createAuthenticatedClient,
  createCommonUser,
} from "../../fixtures/auth.fixture";
import { ApiClient } from "../../client/ApiClient";
import { AllureHelper } from "../../utils/allure-helper";

test.describe.serial("SEC-RACE - Race Condition", () => {
  let adminClient: ApiClient;
  let userAClient: ApiClient;
  let userBClient: ApiClient;
  let userAApiContext: { dispose: () => Promise<void> };
  let userBApiContext: { dispose: () => Promise<void> };
  let productId: string;
  let userAEmail: string;
  let userBEmail: string;

  test.beforeAll(async () => {
    // Cria admin pra gerenciar os produtos
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;

    // Cria dois usuários comuns que vão "brigar" pelo mesmo produto
    const userA = await createCommonUser();
    userAClient = userA.client;
    userAApiContext = userA.apiContext;
    userAEmail = userA.email;

    const userB = await createCommonUser();
    userBClient = userB.client;
    userBApiContext = userB.apiContext;
    userBEmail = userB.email;

    // Cria um produto com estoque MUITO limitado - só 1 unidade
    // Se mais de um usuário conseguir comprar, temos race condition
    const prodResponse = await adminClient.post("/produtos", {
      nome: `Produto Race Condition ${Date.now()}`,
      preco: 50,
      descricao: "Apenas 1 unidade disponivel - teste de concorrencia",
      quantidade: 1,
    });

    if (prodResponse.status() === 201) {
      const body = await prodResponse.json();
      productId = body._id;
      console.log(`[RACE] Produto criado: ${productId} (estoque: 1)`);
    } else {
      console.warn(
        "[RACE] Não foi possível criar o produto. Testes serão pulados.",
      );
    }
  });

  test.afterAll(async () => {
    // Limpa o produto criado
    if (productId) {
      await adminClient.delete(`/produtos/${productId}`).catch(() => {});
    }
    if (userAApiContext) {
      await userAApiContext.dispose().catch(() => {});
    }
    if (userBApiContext) {
      await userBApiContext.dispose().catch(() => {});
    }
  });

  // ------------------------------------------------------------------
  // SEC-RACE-01: Compra simultânea do último item em estoque
  // ------------------------------------------------------------------
  test("SEC-RACE-01: Múltiplos usuários comprando o último item ao mesmo tempo", async () => {
    const descricaoBase =
      "Dois usuários tentam comprar o mesmo produto com estoque = 1 ao mesmo tempo. " +
      "Se ambos conseguirem, o estoque fica negativo e a API tem race condition. " +
      "Esperado: apenas 1 usuário consegue comprar, o outro recebe erro de estoque.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "race-condition", "business-logic");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-RACE-01");
    AllureHelper.addFeature("Segurança - Lógica de Negócio");
    AllureHelper.addStory("Race Condition - Compra Simultânea");

    const alertas: string[] = [];

    if (!productId) {
      console.warn("[RACE] productId não disponível. Pulando teste.");
      return;
    }

    // Primeiro, cada usuário precisa criar um carrinho e adicionar o produto
    // Endpoint da ServeRest: POST /carrinhos com { produtos: [{ idProduto, quantidade }] }

    // Função auxiliar pra criar carrinho com o produto - sem duplicar código
    async function criarCarrinhoComProduto(
      client: ApiClient,
      productId: string,
      userLabel: string,
    ): Promise<string | null> {
      const response = await client.post("/carrinhos", {
        produtos: [
          {
            idProduto: productId,
            quantidade: 1,
          },
        ],
      });

      if (response.status() === 201) {
        const body = await response.json();
        console.log(`[RACE] Carrinho criado para ${userLabel}: ${body._id}`);
        return body._id;
      }

      console.warn(
        `[RACE] Falha ao criar carrinho para ${userLabel}: ${response.status()}`,
      );
      return null;
    }

    // Cria carrinhos para ambos - isso é preparação, não é o ataque em si
    const cartIdA = await criarCarrinhoComProduto(
      userAClient,
      productId,
      "Usuario A",
    );
    const cartIdB = await criarCarrinhoComProduto(
      userBClient,
      productId,
      "Usuario B",
    );

    if (!cartIdA || !cartIdB) {
      console.warn(
        "[RACE] Não foi possível criar os carrinhos. Abortando teste.",
      );
      // Limpa o que conseguiu criar
      if (cartIdA)
        await userAClient.delete(`/carrinhos/${cartIdA}`).catch(() => {});
      if (cartIdB)
        await userBClient.delete(`/carrinhos/${cartIdB}`).catch(() => {});
      return;
    }

    // Agora sim: dispara as duas compras AO MESMO TEMPO
    // Promise.all é exatamente o que simula a condição de corrida
    console.log("[RACE] Disparando compras simultaneas...");

    const resultados = await Promise.allSettled([
      userAClient.post(`/carrinhos/${cartIdA}/comprar`, {}),
      userBClient.post(`/carrinhos/${cartIdB}/comprar`, {}),
    ]);

    // Analisa os resultados
    let comprasBemSucedidas = 0;
    const detalhes: any[] = [];

    for (let i = 0; i < resultados.length; i++) {
      const resultado = resultados[i];
      const usuario = i === 0 ? "Usuario A" : "Usuario B";

      if (resultado.status === "fulfilled") {
        const response = resultado.value;
        const status = response.status();
        const body = await response.text().catch(() => "Erro ao ler resposta");

        if (status === 200 || status === 201) {
          comprasBemSucedidas++;
        }

        detalhes.push({
          usuario,
          status,
          body: body.substring(0, 200),
        });

        console.log(`[RACE] ${usuario}: status ${status}`);
      } else {
        detalhes.push({
          usuario,
          erro: resultado.reason?.message || "Erro desconhecido",
        });
        console.log(`[RACE] ${usuario}: erro - ${resultado.reason?.message}`);
      }
    }

    // Verifica o estoque final
    const estoqueResponse = await adminClient.get(`/produtos/${productId}`);
    let estoqueFinal: number | null = null;

    if (estoqueResponse.status() === 200) {
      const produto = await estoqueResponse.json();
      estoqueFinal = produto.quantidade;
      console.log(`[RACE] Estoque final: ${estoqueFinal}`);
    }

    // Documenta tudo
    await AllureHelper.addAttachment(
      "Resultado Race Condition",
      JSON.stringify(
        {
          produto_id: productId,
          estoque_inicial: 1,
          estoque_final: estoqueFinal,
          compras_bem_sucedidas: comprasBemSucedidas,
          detalhes,
        },
        null,
        2,
      ),
      "application/json",
    );

    // Avalia o resultado
    if (comprasBemSucedidas > 1) {
      alertas.push(
        `[ALERTA CRITICO] Race Condition confirmada: ${comprasBemSucedidas} usuários compraram o mesmo item com estoque 1`,
      );
      console.log(
        "[RACE] VULNERABILIDADE: Mais de um usuário comprou o ultimo item",
      );
    } else if (
      comprasBemSucedidas === 1 &&
      (estoqueFinal === 0 || estoqueFinal === null)
    ) {
      console.log(
        "[RACE] Apenas um usuário conseguiu comprar - comportamento esperado.",
      );
    } else if (comprasBemSucedidas === 0) {
      console.log(
        "[RACE] Nenhum usuário conseguiu comprar - pode ser bloqueio de segurança ou erro.",
      );
      alertas.push(
        "[ALERTA] Nenhuma compra foi concluída - verificar se API bloqueou ambas",
      );
    }

    if (estoqueFinal !== null && estoqueFinal < 0) {
      alertas.push(
        `[ALERTA CRITICO] Estoque negativo: ${estoqueFinal} - inconsistência de dados`,
      );
      console.log("[RACE] VULNERABILIDADE: Estoque ficou negativo");
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    // Limpeza dos carrinhos (se ainda existirem)
    await userAClient.delete(`/carrinhos/${cartIdA}`).catch(() => {});
    await userBClient.delete(`/carrinhos/${cartIdB}`).catch(() => {});
  });

  // ------------------------------------------------------------------
  // SEC-RACE-02: Vários usuários comprando ao mesmo tempo (5 concorrentes)
  // ------------------------------------------------------------------
  test("SEC-RACE-02: Cinco usuários comprando produto com estoque limitado ao mesmo tempo", async () => {
    const descricaoBase =
      "Cinco usuários tentam comprar um produto com estoque = 2 ao mesmo tempo. " +
      "Apenas 2 deveriam conseguir. Se mais de 2 conseguirem, race condition. " +
      "Sei que poderia ter usado um loop mais elegante, mas assim fica claro o teste.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "race-condition", "business-logic");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-RACE-02");
    AllureHelper.addFeature("Segurança - Lógica de Negócio");
    AllureHelper.addStory("Race Condition - Alta Concorrência");

    const alertas: string[] = [];

    // Cria um produto novo com estoque 2
    const prodResponse = await adminClient.post("/produtos", {
      nome: `Produto Alta Concorrencia ${Date.now()}`,
      preco: 100,
      descricao: "Estoque 2 - 5 usuarios tentando comprar",
      quantidade: 2,
    });

    let novoProductId: string | null = null;

    if (prodResponse.status() === 201) {
      const body = await prodResponse.json();
      novoProductId = body._id;
      console.log(
        `[RACE] Produto concorrencia criado: ${novoProductId} (estoque: 2)`,
      );
    } else {
      console.warn(
        "[RACE] Não foi possível criar produto para teste de alta concorrência.",
      );
      return;
    }

    // Cria 5 usuários temporários - gambiarra porque a fixture só cria comum/admin
    // O ideal seria ter uma factory de usuários, mas pra esse teste tá ok
    const usuarios: Array<{
      client: ApiClient;
      context: { dispose: () => Promise<void> };
      cartId: string | null;
    }> = [];

    for (let i = 0; i < 5; i++) {
      const ctx = await request.newContext({
        baseURL: process.env.API_BASE_URL || "https://serverest.dev",
      });
      const client = new ApiClient(
        ctx,
        process.env.API_BASE_URL || "https://serverest.dev",
      );

      const email = `race_user_${i}_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

      await client.post("/usuarios", {
        nome: `Concorrente ${i}`,
        email: email,
        password: "Senha@123",
        administrador: "false",
      });

      await client.login(email, "Senha@123");

      // Cria carrinho com o produto
      const cartResponse = await client.post("/carrinhos", {
        produtos: [{ idProduto: novoProductId, quantidade: 1 }],
      });

      let cartId: string | null = null;
      if (cartResponse.status() === 201) {
        const cartBody = await cartResponse.json();
        cartId = cartBody._id;
      }

      usuarios.push({ client, context: ctx, cartId });
    }

    // Filtra quem conseguiu carrinho
    const usuariosComCarrinho = usuarios.filter((u) => u.cartId !== null);
    console.log(
      `[RACE] ${usuariosComCarrinho.length}/5 usuários com carrinho criado`,
    );

    if (usuariosComCarrinho.length < 2) {
      console.warn("[RACE] Poucos carrinhos criados. Abortando teste.");
      for (const u of usuarios) {
        if (u.cartId)
          await u.client.delete(`/carrinhos/${u.cartId}`).catch(() => {});
        await u.context.dispose().catch(() => {});
      }
      await adminClient.delete(`/produtos/${novoProductId}`).catch(() => {});
      return;
    }

    // Dispara todas as compras ao mesmo tempo
    console.log(
      `[RACE] Disparando ${usuariosComCarrinho.length} compras simultaneas...`,
    );

    const promessas = usuariosComCarrinho.map((u) =>
      u.client.post(`/carrinhos/${u.cartId}/comprar`, {}),
    );

    const resultados = await Promise.allSettled(promessas);

    let comprasBemSucedidas = 0;
    for (const resultado of resultados) {
      if (resultado.status === "fulfilled") {
        const status = resultado.value.status();
        if (status === 200 || status === 201) {
          comprasBemSucedidas++;
        }
      }
    }

    // Verifica estoque final
    const estoqueResponse = await adminClient.get(`/produtos/${novoProductId}`);
    let estoqueFinal: number | null = null;
    if (estoqueResponse.status() === 200) {
      const produto = await estoqueResponse.json();
      estoqueFinal = produto.quantidade;
      console.log(`[RACE] Estoque final: ${estoqueFinal}`);
    }

    await AllureHelper.addAttachment(
      "Resultado Alta Concorrência",
      JSON.stringify(
        {
          produto_id: novoProductId,
          estoque_inicial: 2,
          estoque_final: estoqueFinal,
          usuarios_total: 5,
          usuarios_com_carrinho: usuariosComCarrinho.length,
          compras_bem_sucedidas: comprasBemSucedidas,
        },
        null,
        2,
      ),
      "application/json",
    );

    if (comprasBemSucedidas > 2) {
      alertas.push(
        `[ALERTA CRITICO] Race Condition: ${comprasBemSucedidas} compras com estoque de apenas 2`,
      );
      console.log(
        "[RACE] VULNERABILIDADE: Mais compras que estoque disponível",
      );
    } else {
      console.log(
        `[RACE] ${comprasBemSucedidas} compras concluídas - dentro do estoque.`,
      );
    }

    if (estoqueFinal !== null && estoqueFinal < 0) {
      alertas.push(`[ALERTA CRITICO] Estoque negativo: ${estoqueFinal}`);
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    // Limpeza
    for (const u of usuarios) {
      if (u.cartId)
        await u.client.delete(`/carrinhos/${u.cartId}`).catch(() => {});
      await u.context.dispose().catch(() => {});
    }
    await adminClient.delete(`/produtos/${novoProductId}`).catch(() => {});
  });
});
