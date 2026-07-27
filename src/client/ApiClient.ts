import { APIRequestContext, APIResponse } from "@playwright/test";

export interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, string | number>;
  data?: Record<string, unknown>;
}

export class ApiClient {
  private context: APIRequestContext;
  private baseUrl: string;
  private token: string | null = null;

  constructor(context: APIRequestContext, baseUrl: string) {
    if (!baseUrl || baseUrl.trim() === "") {
      throw new Error("API_BASE_URL não configurada");
    }
    this.context = context;
    this.baseUrl = baseUrl;
  }

  /**
   * Define o token de autenticação
   */
  setToken(token: string): void {
    this.token = token;
  }

  /**
   * Obtém o token atual
   */
  getToken(): string | null {
    return this.token;
  }

  /**
   * Faz login na API
   */
  async login(
    email: string,
    password: string,
  ): Promise<{ authorization: string }> {
    const response = await this.post("/login", { email, password }, false);
    const data = (await response.json()) as {
      authorization?: string;
      message?: string;
    };

    if (response.status() !== 200) {
      throw new Error(
        `Login falhou (${response.status()}): ${data.message || "Erro desconhecido"}`,
      );
    }

    if (!data.authorization) {
      throw new Error("Resposta de login não contém token");
    }

    this.token = data.authorization;
    return { authorization: data.authorization };
  }

  /**
   * Faz uma requisição GET
   */
  async get(
    path: string,
    authenticated: boolean = true,
    options?: RequestOptions,
  ): Promise<APIResponse> {
    return this.request("GET", path, authenticated, options);
  }

  /**
   * Faz uma requisição POST
   */
  async post(
    path: string,
    data?: Record<string, unknown>,
    authenticated: boolean = true,
    options?: RequestOptions,
  ): Promise<APIResponse> {
    return this.request("POST", path, authenticated, { ...options, data });
  }

  /**
   * Faz uma requisição PUT
   */
  async put(
    path: string,
    data?: Record<string, unknown>,
    authenticated: boolean = true,
    options?: RequestOptions,
  ): Promise<APIResponse> {
    return this.request("PUT", path, authenticated, { ...options, data });
  }

  /**
   * Faz uma requisição DELETE
   */
  async delete(
    path: string,
    authenticated: boolean = true,
    options?: RequestOptions,
  ): Promise<APIResponse> {
    return this.request("DELETE", path, authenticated, options);
  }

  /**
   * Método genérico para requisições HTTP usando fetch do Playwright
   */
  private async request(
    method: string,
    path: string,
    authenticated: boolean = true,
    options?: RequestOptions,
  ): Promise<APIResponse> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...options?.headers,
    };

    if (authenticated && this.token) {
      headers["Authorization"] = this.token;
    }

    const url = `${this.baseUrl}${path}`;

    const fetchOptions: {
      method: string;
      headers: Record<string, string>;
      params?: Record<string, string | number>;
      data?: Record<string, unknown>;
    } = {
      method,
      headers,
    };

    if (options?.params) {
      fetchOptions.params = options.params;
    }

    if (options?.data) {
      fetchOptions.data = options.data;
    }

    const response = await this.context.fetch(url, fetchOptions);

    if (authenticated && response.status() === 401) {
      console.warn("⚠️ Token pode ter expirado ou ser inválido");
    }

    return response;
  }
}
