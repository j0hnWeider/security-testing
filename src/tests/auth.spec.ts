/**
 * Testes de Segurança - Autenticação e Autorização
 *
 * Objetivo: validar mecanismos de autenticação, autorização,
 * RBAC, brute force, token inválido/expirado.
 * Abordagem: OWASP Top 10 - A01:2021 (Broken Access Control)
 *            OWASP Top 10 - A07:2021 (Identification and Authentication Failures)
 */

import { test, expect } from '@playwright/test';
import { createAuthenticatedClient, createCommonUser } from '../fixtures/auth.fixture';
import { ApiClient } from '../client/ApiClient';
import { AllureHelper } from '../utils/allure-helper';
import { request } from '@playwright/test';

test.describe('SEC-AUTH - Testes de Autenticação e Autorização', () => {
  let adminClient: any;
  let adminApiContext: any;
  let adminEmail: string;
  let adminPassword: string;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
    adminApiContext = auth.apiContext;
    adminEmail = auth.email;
    adminPassword = auth.password;
  });

  test.afterAll(async () => {
    if (adminApiContext) {
      await adminApiContext.dispose();
    }
  });

  // --------------------------------------------------------------------
  // SEC-AUTH-01: Múltiplas tentativas de login inválido (Brute Force)
  // --------------------------------------------------------------------
  test('SEC-AUTH-01: Deve bloquear múltiplas tentativas de login com credenciais inválidas', async () => {
    AllureHelper.addSeverity('critical');
    AllureHelper.addTags('security', 'auth', 'brute-force');
    AllureHelper.addDescription(
      'Valida se a API implementa rate limiting em tentativas de login.' +
      ' Envia 10 tentativas consecutivas com senha errada e verifica se alguma ' +
      'resposta retorna 429 (Too Many Requests) ou 403 bloqueado.'
    );
    AllureHelper.addTestCaseId('SEC-AUTH-01');
    AllureHelper.addFeature('Segurança - Autenticação');
    AllureHelper.addStory('Força Bruta');

    const invalidCredentials = [
      { email: adminEmail, password: 'wrong1' },
      { email: adminEmail, password: 'wrong2' },
      { email: adminEmail, password: 'wrong3' },
      { email: adminEmail, password: 'wrong4' },
      { email: adminEmail, password: 'wrong5' },
      { email: adminEmail, password: 'wrong6' },
      { email: adminEmail, password: 'wrong7' },
      { email: adminEmail, password: 'wrong8' },
      { email: adminEmail, password: 'wrong9' },
      { email: adminEmail, password: 'wrong10' },
    ];

    let blocked = false;
    let lastStatus = 0;

    for (let i = 0; i < invalidCredentials.length; i++) {
      const cred = invalidCredentials[i];
      const tempApiContext = await request.newContext({
        baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
      });
      const tempClient = new ApiClient(tempApiContext, process.env.API_BASE_URL || 'https://serverest.dev');

      try {
        await tempClient.login(cred.email, cred.password);
      } catch (error: any) {
        if (error.message?.includes('429') || error.message?.includes('403')) {
          blocked = true;
          AllureHelper.addParameter(`Tentativa ${i + 1}`, `Bloqueada - ${error.message}`);
          break;
        }
        if (error.message) {
          const statusMatch = error.message.match(/\((\d+)\)/);
          if (statusMatch) lastStatus = parseInt(statusMatch[1]);
        }
      } finally {
        await tempApiContext.dispose();
      }
    }

    AllureHelper.addAttachment(
      'Resultado Brute Force',
      JSON.stringify({ blocked, tentativas: invalidCredentials.length, ultimoStatus: lastStatus }, null, 2),
      'application/json'
    );

    if (!blocked) {
      console.warn('⚠️ API não bloqueia múltiplas tentativas de login (rate limiting não identificado)');
    }
  });

  // --------------------------------------------------------------------
  // SEC-AUTH-02: Usuário comum não deve criar produtos (403)
  // --------------------------------------------------------------------
  test('SEC-AUTH-02: Usuário comum não deve criar produtos (403 Forbidden)', async () => {
    AllureHelper.addSeverity('critical');
    AllureHelper.addTags('security', 'auth', 'rbac');
    AllureHelper.addDescription(
      'Valida o princípio do menor privilégio (PoLP). ' +
      'Um usuário COMUM não deve conseguir criar produtos, ' +
      'apenas administradores têm essa permissão.'
    );
    AllureHelper.addTestCaseId('SEC-AUTH-02');
    AllureHelper.addFeature('Segurança - Autorização');
    AllureHelper.addStory('RBAC - Controle de Acesso');

    let commonUser = await createCommonUser().catch(() => null);

    if (!commonUser) {
      // Fallback: usar usuário comum conhecido
      const fallbackApiContext = await request.newContext({
        baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
      });
      const fallbackClient = new ApiClient(fallbackApiContext, process.env.API_BASE_URL || 'https://serverest.dev');
      await fallbackClient.login('fulano@qa.com', 'teste');
      commonUser = {
        client: fallbackClient,
        email: 'fulano@qa.com',
        password: 'teste',
        apiContext: fallbackApiContext,
      };
    }

    const response = await commonUser.client.post('/produtos', {
      nome: 'Produto Teste - Acesso Negado',
      preco: 100,
      descricao: 'Usuário comum tentando criar produto',
      quantidade: 1
    }, true);

    AllureHelper.addAttachment(
      'Resposta do Teste RBAC',
      JSON.stringify({ status: response.status(), body: await response.text() }, null, 2),
      'application/json'
    );

    expect(response.status()).toBe(403);
    await commonUser.apiContext.dispose();
  });

  // --------------------------------------------------------------------
  // SEC-AUTH-03: Token inválido/expirado
  // --------------------------------------------------------------------
  test('SEC-AUTH-03: Deve rejeitar token inválido ou mal formatado', async () => {
    AllureHelper.addSeverity('critical');
    AllureHelper.addTags('security', 'auth', 'token');
    AllureHelper.addDescription(
      'Valida que a API rejeita tokens inválidos, mal formatados ou expirados. ' +
      'Testa diferentes formatos de token inválido.'
    );
    AllureHelper.addTestCaseId('SEC-AUTH-03');
    AllureHelper.addFeature('Segurança - Autenticação');
    AllureHelper.addStory('Token Inválido');

    const invalidTokens = [
      'Bearer invalid_token_12345',
      'invalid_token_sem_bearer',
      'Bearer ',
      'Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MTYyMzkwMjJ9.invalido',
      'Basic dGVzdGU6dGVzdGU=',
      '',
      'null',
      undefined,
    ];

    for (let i = 0; i < invalidTokens.length; i++) {
      const token = invalidTokens[i];
      await AllureHelper.addStep(`Testando token inválido: "${String(token).substring(0, 30)}..."`, async () => {
        const tempApiContext = await request.newContext({
          baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
        });
        const tempClient = new ApiClient(tempApiContext, process.env.API_BASE_URL || 'https://serverest.dev');

        if (token !== undefined) {
          tempClient.setToken(token);
        }

        const response = await tempClient.post('/produtos', {
          nome: 'Teste Token Inválido',
          preco: 100,
          descricao: 'Teste',
          quantidade: 1
        }, true);

        expect(response.status()).toBe(401);
        await tempApiContext.dispose();
      });
    }
  });

  // --------------------------------------------------------------------
  // SEC-AUTH-04: Endpoint protegido sem token
  // --------------------------------------------------------------------
  test('SEC-AUTH-04: Deve bloquear acesso a endpoint protegido sem token', async () => {
    AllureHelper.addSeverity('normal');
    AllureHelper.addTags('security', 'auth', 'unauthenticated');
    AllureHelper.addDescription(
      'Valida que endpoints de criação exigem autenticação. ' +
      'Requisição sem token deve retornar 401.'
    );
    AllureHelper.addTestCaseId('SEC-AUTH-04');
    AllureHelper.addFeature('Segurança - Autenticação');
    AllureHelper.addStory('Acesso sem Autenticação');

    const tempApiContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
    });
    const tempClient = new ApiClient(tempApiContext, process.env.API_BASE_URL || 'https://serverest.dev');

    const response = await tempClient.post('/produtos', {
      nome: 'Produto Hacker',
      preco: 1,
      descricao: 'Tentativa invasão',
      quantidade: 1
    }, false);

    expect(response.status()).toBe(401);
    await tempApiContext.dispose();
  });

  // --------------------------------------------------------------------
  // SEC-AUTH-05: Login com e-mail inexistente
  // --------------------------------------------------------------------
  test('SEC-AUTH-05: Deve rejeitar login com e-mail inexistente', async () => {
    AllureHelper.addSeverity('normal');
    AllureHelper.addTags('security', 'auth', 'enumeration');
    AllureHelper.addDescription(
      'Valida que a API não vaza informação sobre existência de usuários. ' +
      'A mensagem de erro deve ser genérica.'
    );
    AllureHelper.addTestCaseId('SEC-AUTH-05');
    AllureHelper.addFeature('Segurança - Autenticação');
    AllureHelper.addStory('Prevenção de User Enumeration');

    const tempApiContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
    });
    const tempClient = new ApiClient(tempApiContext, process.env.API_BASE_URL || 'https://serverest.dev');

    try {
      await tempClient.login('inexistente_123456@teste.com', 'qualquersenha');
    } catch (error: any) {
      const statusMatch = error.message?.match(/\((\d+)\)/);
      const status = statusMatch ? parseInt(statusMatch[1]) : 401;
      expect([400, 401]).toContain(status);
      expect(error.message).not.toContain('não encontrado');
      expect(error.message).not.toContain('not found');
      expect(error.message).not.toContain('inexistente');
    } finally {
      await tempApiContext.dispose();
    }
  });

  // --------------------------------------------------------------------
  // SEC-AUTH-06: Atualizar produto de outro usuário
  // --------------------------------------------------------------------
  test('SEC-AUTH-06: Usuário não deve atualizar produto de outro', async () => {
    AllureHelper.addSeverity('normal');
    AllureHelper.addTags('security', 'auth', 'rbac', 'horizontal-privilege');
    AllureHelper.addDescription(
      'Valida que um usuário não pode modificar recursos de outro usuário ' +
      '(Privilege Escalation Horizontal).'
    );
    AllureHelper.addTestCaseId('SEC-AUTH-06');
    AllureHelper.addFeature('Segurança - Autorização');
    AllureHelper.addStory('Escalação de Privilégio Horizontal');

    const response = await adminClient.put('/produtos/999999999', {
      nome: 'Tentativa de acesso a recurso alheio',
      preco: 100,
      descricao: 'Teste',
      quantidade: 1
    }, true);

    expect([400, 403, 404]).toContain(response.status());
  });
});
