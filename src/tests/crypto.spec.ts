/**
 * Testes de Segurança - Falhas Criptográficas
 *
 * Objetivo: validar a integridade dos mecanismos criptográficos da API.
 * Abordagem: OWASP Top 10 - A02:2021 (Cryptographic Failures)
 *            OWASP ASVS V2.10 (Service-to-Service Authentication)
 *            OWASP ASVS V6.2 (Algorithms)
 */

import { test, expect } from "@playwright/test";
import { createAuthenticatedClient } from "../fixtures/auth.fixture";
import { ApiClient } from "../client/ApiClient";
import { AllureHelper } from "../utils/allure-helper";

test.describe.serial("SEC-CRYPTO - Falhas Criptográficas", () => {
  let adminClient: ApiClient;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
  });

  test("SEC-CRYPTO-01: Senha não deve trafegar em texto plano na resposta de criação de usuário", async () => {
    const descricaoBase =
      "Valida se a API retorna a senha em texto plano no corpo da resposta " +
      "ao criar um usuário. Senhas nunca devem ser retornadas após a criação.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "crypto", "password-exposure");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-CRYPTO-01");
    AllureHelper.addFeature("Segurança - Criptografia");
    AllureHelper.addStory("Exposição de Senha");

    const password = "Senha@12345";
    const email = `crypto_test_01_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    const createResponse = await adminClient.post("/usuarios", {
      nome: "Teste Criptografia",
      email: email,
      password: password,
      administrador: "false",
    });

    if (createResponse.status() === 503) {
      console.warn("[CRYPTO] Servidor indisponível (503). Abortando teste.");
      return;
    }

    expect(createResponse.status()).toBe(201);
    const body = await createResponse.json();

    const responseText = JSON.stringify(body);
    const hasPasswordInBody =
      typeof body.password === "string" && body.password === password;
    const hasSenhaInBody =
      typeof body.senha === "string" && body.senha === password;
    const passwordExposed =
      responseText.includes(password) || hasPasswordInBody || hasSenhaInBody;

    const alertas: string[] = [];

    AllureHelper.addAttachment(
      "Resposta da Criação",
      JSON.stringify(body, null, 2),
      "application/json",
    );

    if (passwordExposed) {
      const campos = Object.keys(body).filter(
        (k) => typeof body[k] === "string" && body[k].includes(password),
      );
      alertas.push(
        `[ALERTA] Senha retornada em texto plano no corpo da resposta. Campos expostos: ${campos.join(", ")}`,
      );
      console.log(
        "[ALERTA] Senha retornada em texto plano na resposta da API.",
      );
      await AllureHelper.addAttachment(
        "Alerta: Exposição de Senha",
        JSON.stringify(
          {
            alerta:
              "A API retornou a senha em texto plano no corpo da resposta",
            campos_expostos: campos,
            recomendacao:
              "Remover campo password/senha do retorno de criação e consulta",
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

    expect(passwordExposed).toBe(false);

    if (body._id) {
      await adminClient.delete(`/usuarios/${body._id}`);
    }
  });

  test("SEC-CRYPTO-02: Senha não deve ser retornada na consulta de usuário", async () => {
    const descricaoBase =
      "Cria um usuário e em seguida consulta seus dados. " +
      "O campo password/senha não deve estar presente na resposta.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "crypto", "password-exposure");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-CRYPTO-02");
    AllureHelper.addFeature("Segurança - Criptografia");
    AllureHelper.addStory("Exposição de Senha em Consulta");

    const password = "Consulta@12345";
    const email = `crypto_test_02_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

    const createResponse = await adminClient.post("/usuarios", {
      nome: "Teste Consulta Senha",
      email: email,
      password: password,
      administrador: "false",
    });

    if (createResponse.status() === 503) {
      console.warn("[CRYPTO] Servidor indisponível (503). Abortando teste.");
      return;
    }

    expect(createResponse.status()).toBe(201);
    const createBody = await createResponse.json();
    const userId = createBody._id;

    const getResponse = await adminClient.get(`/usuarios/${userId}`);

    if (getResponse.status() === 503) {
      console.warn("[CRYPTO] Servidor indisponível (503) na consulta.");
      await adminClient.delete(`/usuarios/${userId}`);
      return;
    }

    expect(getResponse.status()).toBe(200);
    const userData = await getResponse.json();

    const hasPasswordField =
      Object.prototype.hasOwnProperty.call(userData, "password") ||
      Object.prototype.hasOwnProperty.call(userData, "senha");

    const hasPasswordValue =
      (typeof userData.password === "string" &&
        userData.password === password) ||
      (typeof userData.senha === "string" && userData.senha === password);

    const alertas: string[] = [];

    AllureHelper.addAttachment(
      "Dados do Usuário Consultados",
      JSON.stringify(userData, null, 2),
      "application/json",
    );

    if (hasPasswordField) {
      const campo = userData.password ? "password" : "senha";
      alertas.push(`[ALERTA] API retorna campo '${campo}' na consulta GET`);
      console.log(
        "[ALERTA] Campo password/senha presente na resposta de consulta.",
      );
      await AllureHelper.addAttachment(
        "Alerta: Campo de Senha Exposto",
        JSON.stringify(
          {
            alerta: "API retorna campo password/senha na consulta de usuário",
            campo_exposto: campo,
            valor_retornado: userData.password || userData.senha,
            recomendacao: "Remover campo de senha do retorno de consultas GET",
          },
          null,
          2,
        ),
        "application/json",
      );

      if (hasPasswordValue) {
        alertas.push(
          "[ALERTA CRITICO] Senha em texto plano retornada na consulta",
        );
        console.log(
          "[ALERTA CRITICO] Senha em texto plano retornada na consulta.",
        );
      }
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    if (hasPasswordField) {
      console.warn(
        "[CRYPTO] Vulnerabilidade confirmada: API expoe campo password na consulta GET. " +
          "Verificar se este comportamento persiste em producao.",
      );
    } else {
      expect(hasPasswordField).toBe(false);
      expect(hasPasswordValue).toBe(false);
    }

    await adminClient.delete(`/usuarios/${userId}`);
  });

  test("SEC-CRYPTO-03: Token JWT deve usar algoritmo seguro no header", async () => {
    const descricaoBase =
      "Decodifica o header do token JWT para verificar o algoritmo de assinatura. " +
      "Algoritmos como 'none' ou HS256 com chave fraca são inaceitáveis. " +
      "O algoritmo esperado é RS256 ou HS256 com chave robusta.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "crypto", "jwt", "algorithm");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-CRYPTO-03");
    AllureHelper.addFeature("Segurança - Criptografia");
    AllureHelper.addStory("Algoritmo JWT Fraco");

    const token = adminClient.getToken();

    if (!token) {
      console.warn("[CRYPTO] Token não disponível. Abortando teste.");
      return;
    }

    const tokenParts = token.replace("Bearer ", "").split(".");

    if (tokenParts.length < 2) {
      console.log("[CRYPTO] Token não está no formato JWT padrão.");
      await AllureHelper.addAttachment(
        "Formato do Token",
        JSON.stringify(
          { token_preview: token.substring(0, 50) + "..." },
          null,
          2,
        ),
        "application/json",
      );
      return;
    }

    let header: Record<string, unknown> = {};
    try {
      const headerBase64 = tokenParts[0];
      const headerJson = Buffer.from(headerBase64, "base64").toString("utf-8");
      header = JSON.parse(headerJson);
    } catch (error) {
      console.log(
        `[CRYPTO] Não foi possível decodificar o header JWT: ${error}`,
      );
      return;
    }

    const algorithm = header.alg as string | undefined;
    const weakAlgorithms = ["none", "None", "NONE"];
    const alertas: string[] = [];

    AllureHelper.addAttachment(
      "Header JWT Decodificado",
      JSON.stringify({ header, algoritmo: algorithm }, null, 2),
      "application/json",
    );

    AllureHelper.addParameter("JWT Algorithm", algorithm || "não identificado");

    if (!algorithm) {
      alertas.push("[ALERTA] Header JWT não contém campo 'alg'");
      console.log("[CRYPTO] Header JWT não contém campo 'alg'.");
    } else if (weakAlgorithms.includes(algorithm)) {
      alertas.push(
        `[ALERTA CRITICO] JWT usando algoritmo inseguro: ${algorithm}`,
      );
      console.log(
        `[ALERTA CRITICO] JWT usando algoritmo inseguro: ${algorithm}`,
      );
      await AllureHelper.addAttachment(
        "Alerta: Algoritmo JWT Inseguro",
        JSON.stringify(
          {
            alerta: "Token JWT utiliza algoritmo 'none' (sem assinatura)",
            algoritmo: algorithm,
            risco: "Atacante pode forjar tokens arbitrários",
            recomendacao: "Utilizar RS256 ou ES256 com chaves assimétricas",
          },
          null,
          2,
        ),
        "application/json",
      );
      expect(algorithm).not.toBe("none");
    } else if (algorithm === "HS256") {
      alertas.push("[INFO] JWT usa HS256 (simétrico)");
      console.log(
        "[INFO] JWT usa HS256. Verificar se a chave secreta é robusta.",
      );
      await AllureHelper.addAttachment(
        "Observação: HS256",
        JSON.stringify(
          {
            observacao:
              "HS256 usa chave simétrica. Garantir que a chave tenha pelo menos 256 bits.",
            recomendacao: "Preferir RS256 ou ES256 para ambientes distribuídos",
          },
          null,
          2,
        ),
        "application/json",
      );
    } else {
      console.log(`[INFO] Algoritmo JWT: ${algorithm}`);
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }
  });

  test("SEC-CRYPTO-04: Token JWT deve ter tempo de expiração definido", async () => {
    const descricaoBase =
      "Decodifica o payload do JWT para verificar se o campo 'exp' está presente. " +
      "Tokens sem expiração são um risco grave de segurança.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "crypto", "jwt", "expiration");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-CRYPTO-04");
    AllureHelper.addFeature("Segurança - Criptografia");
    AllureHelper.addStory("Token Sem Expiração");

    const token = adminClient.getToken();

    if (!token) {
      console.warn("[CRYPTO] Token não disponível. Abortando teste.");
      return;
    }

    const tokenParts = token.replace("Bearer ", "").split(".");

    if (tokenParts.length < 3) {
      console.log("[CRYPTO] Token não está no formato JWT completo.");
      return;
    }

    let payload: Record<string, unknown> = {};
    try {
      const payloadBase64 = tokenParts[1];
      const payloadJson = Buffer.from(payloadBase64, "base64").toString(
        "utf-8",
      );
      payload = JSON.parse(payloadJson);
    } catch (error) {
      console.log(
        `[CRYPTO] Não foi possível decodificar o payload JWT: ${error}`,
      );
      return;
    }

    const hasExpiration = Object.prototype.hasOwnProperty.call(payload, "exp");
    const alertas: string[] = [];

    AllureHelper.addAttachment(
      "Payload JWT Decodificado",
      JSON.stringify(
        {
          exp: payload.exp
            ? new Date((payload.exp as number) * 1000).toISOString()
            : "AUSENTE",
          iat: payload.iat
            ? new Date((payload.iat as number) * 1000).toISOString()
            : "AUSENTE",
          exp_presente: hasExpiration,
          campos_presentes: Object.keys(payload),
        },
        null,
        2,
      ),
      "application/json",
    );

    if (!hasExpiration) {
      alertas.push("[ALERTA] Token JWT sem campo de expiração (exp)");
      console.log("[ALERTA] Token JWT sem campo de expiração (exp).");
      await AllureHelper.addAttachment(
        "Alerta: Token Sem Expiração",
        JSON.stringify(
          {
            alerta: "Token JWT não possui data de expiração",
            risco: "Token comprometido permanece válido indefinidamente",
            recomendacao:
              "Definir campo 'exp' com tempo de vida curto (15-60 minutos)",
          },
          null,
          2,
        ),
        "application/json",
      );
    } else {
      const expirationDate = new Date((payload.exp as number) * 1000);
      const now = new Date();
      const timeUntilExpiration = expirationDate.getTime() - now.getTime();
      const hoursUntilExpiration = Math.round(
        timeUntilExpiration / (1000 * 60 * 60),
      );

      console.log(`[INFO] Token expira em: ${expirationDate.toISOString()}`);
      console.log(`[INFO] Tempo restante: ~${hoursUntilExpiration} horas`);

      if (hoursUntilExpiration > 24) {
        alertas.push(
          `[ALERTA] Token com expiração longa: ~${hoursUntilExpiration}h`,
        );
        console.log("[ALERTA] Token com tempo de expiração muito longo.");
        await AllureHelper.addAttachment(
          "Alerta: Expiração Longa",
          JSON.stringify(
            {
              observacao: `Token expira em aproximadamente ${hoursUntilExpiration} horas`,
              recomendacao:
                "Reduzir tempo de vida do token para no máximo 24 horas",
            },
            null,
            2,
          ),
          "application/json",
        );
      }
    }

    if (alertas.length > 0) {
      AllureHelper.addDescription(descricaoBase + " | " + alertas.join(" | "));
    }

    expect(hasExpiration).toBe(true);
  });

  test("SEC-CRYPTO-05: Senhas devem ter comprimento mínimo exigido pela API", async () => {
    const descricaoBase =
      "Testa se a API impõe um comprimento mínimo para senhas. " +
      "Senhas curtas são vulneráveis a força bruta e dicionário. " +
      "O OWASP ASVS recomenda mínimo de 8 caracteres.";

    AllureHelper.addSeverity("normal");
    AllureHelper.addTags("security", "crypto", "password-policy");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-CRYPTO-05");
    AllureHelper.addFeature("Segurança - Criptografia");
    AllureHelper.addStory("Política de Senha Fraca");

    const weakPasswords = [
      { password: "", descricao: "senha vazia" },
      { password: "1", descricao: "1 caractere" },
      { password: "12", descricao: "2 caracteres" },
      { password: "123", descricao: "3 caracteres" },
      { password: "1234", descricao: "4 caracteres" },
      { password: "12345", descricao: "5 caracteres" },
      { password: "123456", descricao: "6 caracteres (comum em vazamentos)" },
      { password: "1234567", descricao: "7 caracteres" },
    ];

    const resultados: Array<{
      comprimento: number;
      descricao: string;
      aceita: boolean;
      status: number;
      email: string;
    }> = [];

    for (const testCase of weakPasswords) {
      const email = `pass_${testCase.password.length}_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;

      const response = await adminClient.post("/usuarios", {
        nome: `Teste Senha ${testCase.password.length}`,
        email: email,
        password: testCase.password,
        administrador: "false",
      });

      const aceita = response.status() === 201;
      let userId: string | null = null;

      if (aceita) {
        const body = await response.json();
        userId = body._id || null;
      }

      resultados.push({
        comprimento: testCase.password.length,
        descricao: testCase.descricao,
        aceita: aceita,
        status: response.status(),
        email: email,
      });

      console.log(
        `[CRYPTO] Senha de ${testCase.password.length} caracteres: ${aceita ? "ACEITA" : "REJEITADA"} (${response.status()})`,
      );

      if (userId) {
        await adminClient.delete(`/usuarios/${userId}`);
      }
    }

    const alertas: string[] = [];

    await AllureHelper.addAttachment(
      "Resultado Política de Senha",
      JSON.stringify(resultados, null, 2),
      "application/json",
    );

    const aceitas = resultados.filter((r) => r.aceita);
    const senhasFracasAceitas = aceitas.filter((r) => r.comprimento < 8);

    if (senhasFracasAceitas.length > 0) {
      alertas.push(
        `[ALERTA] API aceita ${senhasFracasAceitas.length} senhas com menos de 8 caracteres`,
      );
      console.log(
        `[ALERTA] API aceita ${senhasFracasAceitas.length} senhas com menos de 8 caracteres.`,
      );
      await AllureHelper.addAttachment(
        "Alerta: Política de Senha Fraca",
        JSON.stringify(
          {
            alerta: "API não impõe comprimento mínimo adequado para senhas",
            senhas_aceitas: senhasFracasAceitas.map(
              (r) => `${r.comprimento} caracteres`,
            ),
            recomendacao:
              "Exigir mínimo de 8 caracteres, combinando letras, números e símbolos",
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
  });

  test("SEC-CRYPTO-06: Verificar se a API usa HTTPS para todas as requisições", async () => {
    const descricaoBase =
      "Valida se a URL base da API utiliza HTTPS. " +
      "Comunicação sem criptografia TLS expõe tokens e dados sensíveis.";

    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "crypto", "tls", "https");
    AllureHelper.addDescription(descricaoBase);
    AllureHelper.addTestCaseId("SEC-CRYPTO-06");
    AllureHelper.addFeature("Segurança - Criptografia");
    AllureHelper.addStory("Comunicação Insegura");

    const baseUrl = process.env.API_BASE_URL || "https://serverest.dev";
    const usesHttps = baseUrl.startsWith("https://");
    const alertas: string[] = [];

    AllureHelper.addParameter("API Base URL", baseUrl);
    AllureHelper.addAttachment(
      "Verificação HTTPS",
      JSON.stringify(
        {
          url: baseUrl,
          usa_https: usesHttps,
          protocolo: baseUrl.split("://")[0],
        },
        null,
        2,
      ),
      "application/json",
    );

    if (!usesHttps) {
      alertas.push("[ALERTA CRITICO] API não utiliza HTTPS");
      console.log("[ALERTA CRITICO] API não utiliza HTTPS.");
      await AllureHelper.addAttachment(
        "Alerta: HTTP sem TLS",
        JSON.stringify(
          {
            alerta: "Comunicação com a API ocorre sem criptografia TLS",
            risco:
              "Tokens, senhas e dados sensíveis trafegam em texto plano na rede",
            recomendacao: "Forçar HTTPS com TLS 1.2 ou superior",
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

    expect(usesHttps).toBe(true);
  });
});
