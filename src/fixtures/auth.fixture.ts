import { request, APIRequestContext } from "@playwright/test";
import { ApiClient } from "../client/ApiClient";
import { faker } from "@faker-js/faker";

export interface AuthContext {
  client: ApiClient;
  apiContext: APIRequestContext;
  email: string;
  password: string;
  token?: string;
}

export interface UserData {
  email: string;
  password: string;
  nome: string;
}

export async function createAuthenticatedClient(): Promise<AuthContext> {
  const baseUrl = process.env.API_BASE_URL || "https://serverest.dev";
  const email = process.env.TEST_USER_EMAIL || "admin@teste.com";
  const password = process.env.TEST_PASSWORD || "123456";

  const apiContext = await request.newContext({
    baseURL: baseUrl,
  });

  const client = new ApiClient(apiContext, baseUrl);

  try {
    await client.login(email, password);
  } catch (error) {
    console.warn("Login falhou, criando usuario admin...");
    await createAdminUser(client, email, password);
    await client.login(email, password);
  }

  return {
    client,
    apiContext,
    email,
    password,
  };
}

export async function createCommonUser(): Promise<AuthContext> {
  const baseUrl = process.env.API_BASE_URL || "https://serverest.dev";
  const email = faker.internet.email();
  const password = "teste123";

  const apiContext = await request.newContext({
    baseURL: baseUrl,
  });

  const client = new ApiClient(apiContext, baseUrl);

  await createUser(client, email, password, faker.person.fullName());
  await client.login(email, password);

  return {
    client,
    apiContext,
    email,
    password,
  };
}

async function createAdminUser(
  client: ApiClient,
  email: string,
  password: string,
): Promise<void> {
  await client.post(
    "/usuarios",
    {
      nome: "Admin Teste",
      email: email,
      password: password,
      administrador: "true",
    },
    false,
  );
}

async function createUser(
  client: ApiClient,
  email: string,
  password: string,
  nome: string,
): Promise<void> {
  await client.post(
    "/usuarios",
    {
      nome: nome,
      email: email,
      password: password,
      administrador: "false",
    },
    false,
  );
}

export function getBaseUrl(): string {
  const url = process.env.API_BASE_URL;
  if (!url || url.trim() === "") {
    throw new Error("API_BASE_URL nao configurada no ambiente");
  }
  return url;
}
