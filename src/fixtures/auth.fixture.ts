import { request, APIRequestContext } from "@playwright/test";
import { ApiClient } from "../client/ApiClient";

const API_BASE_URL = process.env.API_BASE_URL || "https://serverest.dev";

/**
 * Cria um novo usuário administrador na API e retorna um cliente autenticado.
 * Isso garante que o teste não dependa de um usuário pré-existente.
 */
export async function createAuthenticatedClient(): Promise<{
  client: ApiClient;
  apiContext: APIRequestContext;
  email: string;
  password: string;
}> {
  const apiContext = await request.newContext({
    baseURL: API_BASE_URL,
  });

  const client = new ApiClient(apiContext, API_BASE_URL);

  // Gera credenciais únicas para evitar conflitos
  const timestamp = Date.now();
  const uniqueEmail = `admin_${timestamp}@qa.com`;
  const password = `Teste@${timestamp}`;

  // 1. Cadastra um novo usuário administrador
  const signUpResponse = await client.post("/usuarios", {
    nome: "Admin Automatizado",
    email: uniqueEmail,
    password: password,
    administrador: "true",
  });

  // Se o cadastro falhar por qualquer motivo, lança erro claro
  if (signUpResponse.status() !== 201) {
    const body = await signUpResponse.text();
    throw new Error(
      `Falha ao criar usuário admin: ${signUpResponse.status()} - ${body}`
    );
  }

  // 2. Realiza o login com o usuário recém-criado
  await client.login(uniqueEmail, password);

  return { client, apiContext, email: uniqueEmail, password };
}

/**
 * Cria um novo usuário comum e retorna um cliente autenticado.
 */
export async function createCommonUser(): Promise<{
  client: ApiClient;
  apiContext: APIRequestContext;
  email: string;
  password: string;
} | null> {
  try {
    const apiContext = await request.newContext({
      baseURL: API_BASE_URL,
    });

    const client = new ApiClient(apiContext, API_BASE_URL);

    const timestamp = Date.now();
    const uniqueEmail = `common_${timestamp}@qa.com`;
    const password = `Common@${timestamp}`;

    // 1. Cadastra um novo usuário comum
    const signUpResponse = await client.post("/usuarios", {
      nome: "Usuario Comum Automatizado",
      email: uniqueEmail,
      password: password,
      administrador: "false",
    });

    if (signUpResponse.status() !== 201) {
      await apiContext.dispose();
      return null;
    }

    // 2. Realiza o login
    await client.login(uniqueEmail, password);

    return { client, apiContext, email: uniqueEmail, password };
  } catch (error) {
    return null;
  }
}
