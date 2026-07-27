import { APIRequestContext, APIResponse } from '@playwright/test';

export class ApiClient {
  private request: APIRequestContext;
  private baseURL: string;
  private token: string | null = null;

  constructor(request: APIRequestContext, baseURL: string) {
    this.request = request;
    this.baseURL = baseURL;
  }

  setToken(token: string): void {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  async login(email: string, password: string): Promise<string> {
    const response = await this.request.post(`${this.baseURL}/login`, {
      data: { email, password },
    });

    if (response.status() !== 200) {
      const errorBody = await response.text();
      throw new Error(`Login falhou (${response.status()}): ${errorBody}`);
    }

    const body = await response.json();
    const token = body.authorization || body.token;

    if (!token) {
      throw new Error(`Login não retornou token. Campos: ${Object.keys(body).join(', ')}`);
    }

    this.token = token;
    return token;
  }

  private getAuthHeader(): Record<string, string> {
    if (!this.token) return {};
    const authValue = this.token.startsWith('Bearer ') ? this.token : `Bearer ${this.token}`;
    return { 'Authorization': authValue };
  }

  async get(endpoint: string, auth: boolean = false): Promise<APIResponse> {
    const headers = auth ? this.getAuthHeader() : {};
    return await this.request.get(`${this.baseURL}${endpoint}`, { headers });
  }

  async post(endpoint: string, data: any, auth: boolean = false): Promise<APIResponse> {
    const headers = auth ? this.getAuthHeader() : {};
    return await this.request.post(`${this.baseURL}${endpoint}`, { data, headers });
  }

  async put(endpoint: string, data: any, auth: boolean = false): Promise<APIResponse> {
    const headers = auth ? this.getAuthHeader() : {};
    return await this.request.put(`${this.baseURL}${endpoint}`, { data, headers });
  }

  async delete(endpoint: string, auth: boolean = false): Promise<APIResponse> {
    const headers = auth ? this.getAuthHeader() : {};
    return await this.request.delete(`${this.baseURL}${endpoint}`, { headers });
  }

  async rawPost(endpoint: string, data: any, customHeaders?: Record<string, string>): Promise<APIResponse> {
    const headers = { ...this.getAuthHeader(), ...customHeaders };
    return await this.request.post(`${this.baseURL}${endpoint}`, { data, headers });
  }

  async rawGet(endpoint: string, customHeaders?: Record<string, string>): Promise<APIResponse> {
    const headers = { ...customHeaders };
    return await this.request.get(`${this.baseURL}${endpoint}`, { headers });
  }
}
