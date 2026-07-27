import { APIRequestContext, request } from "@playwright/test";
import { ApiClient } from "../client/ApiClient";
import { faker } from "@faker-js/faker";

export interface AuthFixture {
  client: ApiClient;
  email: string;
  password: string;
  apiContext: APIRequestContext;
}

/**
 * Retorna a URL base da API a partir das variáveis de ambiente
 */
function getBaseUrl(): string {
  return process.env.API_BASE_URL || "https://serverest.dev";
}

/**
 * Retorna a senha para testes, com fallback seguro
 */
function getTestPassword(): string {
  return process.env.TEST_PASSWORD || "123456";
}

/**
 * Cria uma conta administradora via API e retorna um cliente autenticado
 */
export async function createAuthenticatedClient(): Promise<AuthFixture> {
  const maxRetries = 3;
  let lastError: Error | null = null;
  const baseURL = getBaseUrl();
  const password = getTestPassword();

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const apiContext = await request.newContext({
        baseURL,
        extraHTTPHeaders: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
      });

      const email = `sec_test_${faker.string.alphanumeric(10)}@teste.com`;

      const createResponse = await apiContext.post("/usuarios", {
        data: {
          nome: "Security Tester",
          email,
          password,
          administrador: "true",
        },
      });

      if (createResponse.status() !== 201) {
        const errorBody = await createResponse.text();
        throw new Error(
          `Falha ao criar conta (${createResponse.status()}): ${errorBody}`,
        );
      }

      const client = new ApiClient(apiContext, baseURL);
      await client.login(email, password);

      return { client, email, password, apiContext };
    } catch (error: any) {
      lastError = error;
      console.warn(
        `Tentativa ${attempt}/${maxRetries} falhou: ${error.message}`,
      );
      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  }

  throw new Error(`Falha após ${maxRetries} tentativas: ${lastError?.message}`);
}

/**
 * Cria um usuário COMUM (não administrador) e retorna cliente autenticado
 */
export async function createCommonUser(): Promise<AuthFixture> {
  const baseURL = getBaseUrl();
  const password = getTestPassword();

  const apiContext = await request.newContext({
    baseURL,
    extraHTTPHeaders: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
  });

  const email = `common_${faker.string.alphanumeric(10)}@teste.com`;

  const createResponse = await apiContext.post("/usuarios", {
    data: {
      nome: "Usuario Comum",
      email,
      password,
      administrador: "false",
    },
  });

  if (createResponse.status() !== 201) {
    throw new Error(
      `Falha ao criar usuário comum: ${await createResponse.text()}`,
    );
  }

  const client = new ApiClient(apiContext, baseURL);
  await client.login(email, password);

  return { client, email, password, apiContext };
}
