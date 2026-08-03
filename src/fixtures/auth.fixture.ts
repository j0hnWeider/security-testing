import { request, APIRequestContext } from "@playwright/test";
import { ApiClient } from "../client/ApiClient";

export interface AuthFixture {
  client: ApiClient;
  apiContext: APIRequestContext;
  email: string;
  password: string;
}

export interface CommonUserFixture {
  client: ApiClient;
  apiContext: APIRequestContext;
  email: string;
  password: string;
}

export async function createAuthenticatedClient(): Promise<AuthFixture> {
  const baseURL = process.env.API_BASE_URL || "https://serverest.dev";
  const apiContext = await request.newContext({ baseURL });
  const client = new ApiClient(apiContext, baseURL);

  const timestamp = Date.now();
  const email = `admin_${timestamp}_${Math.random().toString(36).substring(7)}@qa.com`;
  const password = "Teste@123";

  const maxRetries = 3;
  let attempt = 0;

  while (attempt < maxRetries) {
    attempt++;
    try {
      const signUpResponse = await client.post("/usuarios", {
        nome: "Admin Teste",
        email: email,
        password: password,
        administrador: "true",
      });

      if (signUpResponse.status() === 503) {
        console.warn(
          `[AUTH] Servidor indisponível (503). Tentativa ${attempt}/${maxRetries}. Aguardando...`,
        );
        if (attempt === maxRetries) {
          throw new Error(
            `Falha ao criar usuário admin: 503 Service Unavailable após ${maxRetries} tentativas`,
          );
        }
        await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
        continue;
      }

      if (signUpResponse.status() !== 201) {
        const body = await signUpResponse.text();
        throw new Error(
          `Falha ao criar usuário admin: ${signUpResponse.status()} - ${body}`,
        );
      }

      break;
    } catch (error: unknown) {
      if (attempt === maxRetries) {
        throw error;
      }
      console.warn(
        `[AUTH] Erro na tentativa ${attempt}. Tentando novamente...`,
      );
      await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
    }
  }

  await client.login(email, password);

  return {
    client,
    apiContext,
    email,
    password,
  };
}

export async function createCommonUser(): Promise<CommonUserFixture> {
  const baseURL = process.env.API_BASE_URL || "https://serverest.dev";
  const apiContext = await request.newContext({ baseURL });
  const client = new ApiClient(apiContext, baseURL);

  const timestamp = Date.now();
  const email = `common_${timestamp}_${Math.random().toString(36).substring(7)}@qa.com`;
  const password = "Teste@123";

  const maxRetries = 3;
  let attempt = 0;

  while (attempt < maxRetries) {
    attempt++;
    try {
      const signUpResponse = await client.post("/usuarios", {
        nome: "Usuario Comum",
        email: email,
        password: password,
        administrador: "false",
      });

      if (signUpResponse.status() === 503) {
        console.warn(
          `[AUTH] Servidor indisponível (503). Tentativa ${attempt}/${maxRetries}. Aguardando...`,
        );
        if (attempt === maxRetries) {
          throw new Error(
            `Falha ao criar usuário comum: 503 Service Unavailable após ${maxRetries} tentativas`,
          );
        }
        await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
        continue;
      }

      if (signUpResponse.status() !== 201) {
        const body = await signUpResponse.text();
        throw new Error(
          `Falha ao criar usuário comum: ${signUpResponse.status()} - ${body}`,
        );
      }

      break;
    } catch (error: unknown) {
      if (attempt === maxRetries) {
        throw error;
      }
      console.warn(
        `[AUTH] Erro na tentativa ${attempt}. Tentando novamente...`,
      );
      await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
    }
  }

  await client.login(email, password);

  return {
    client,
    apiContext,
    email,
    password,
  };
}
