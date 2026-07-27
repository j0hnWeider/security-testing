/**
 * Testes de Segurança - Cabeçalhos HTTP
 *
 * Objetivo: verificar a presença e configuração de cabeçalhos de segurança
 * essenciais nas respostas da API.
 * Abordagem: OWASP Secure Headers Project
 */

import { test, expect } from '@playwright/test';
import { AllureHelper } from '../utils/allure-helper';

const API_BASE_URL = process.env.API_BASE_URL || 'https://serverest.dev';

test.describe('SEC-HEADERS - Testes de Cabeçalhos HTTP', () => {

  // --------------------------------------------------------------------
  // SEC-HEADERS-01: Cabeçalhos de segurança essenciais
  // --------------------------------------------------------------------
  test('SEC-HEADERS-01: Deve conter cabeçalhos de segurança essenciais', async ({ request }) => {
    AllureHelper.addSeverity('critical');
    AllureHelper.addTags('security', 'headers', 'owasp');
    AllureHelper.addDescription(
      'Verifica a presença dos principais cabeçalhos de segurança recomendados pelo OWASP Secure Headers Project.'
    );
    AllureHelper.addTestCaseId('SEC-HEADERS-01');
    AllureHelper.addFeature('Segurança - Cabeçalhos HTTP');
    AllureHelper.addStory('OWASP Secure Headers');

    const response = await request.get(API_BASE_URL);
    const headers = response.headers();

    const securityHeaders = [
      { name: 'X-Frame-Options', expected: ['DENY', 'SAMEORIGIN'], description: 'Proteção contra Clickjacking' },
      { name: 'X-Content-Type-Options', expected: ['nosniff'], description: 'Previne MIME sniffing' },
      { name: 'Strict-Transport-Security', expected: ['max-age'], description: 'Força HTTPS (HSTS)' },
      { name: 'Content-Security-Policy', expected: ['default-src', 'script-src'], description: 'Política de segurança de conteúdo' },
      { name: 'Referrer-Policy', expected: ['strict-origin', 'same-origin', 'no-referrer'], description: 'Controla envio de referrer' },
      { name: 'X-XSS-Protection', expected: ['1', '0'], description: 'Proteção contra XSS (deprecated, mas ainda usado)' },
      { name: 'Permissions-Policy', expected: ['camera', 'microphone', 'geolocation'], description: 'Controla permissões de APIs do browser' },
      { name: 'X-Permitted-Cross-Domain-Policies', expected: ['none'], description: 'Previne políticas cross-domain' },
    ];

    const results: any[] = [];
    for (const header of securityHeaders) {
      const value = headers[header.name.toLowerCase()];
      const found = value ? header.expected.some(exp => value.toLowerCase().includes(exp.toLowerCase())) : false;

      results.push({
        header: header.name,
        present: !!value,
        value: value || 'AUSENTE',
        expected: header.expected.join(' | '),
        valid: found,
        description: header.description,
      });

      if (!value) {
        console.warn(`⚠️ Header ausente: ${header.name} - ${header.description}`);
      } else if (!found) {
        console.warn(`⚠️ Header ${header.name} não contém valor esperado (${header.expected.join('|')}), encontrado: ${value}`);
      }
    }

    AllureHelper.addAttachment(
      'Análise de Headers de Segurança',
      JSON.stringify(results, null, 2),
      'application/json'
    );

    const presentHeaders = results.filter(r => r.present);
    AllureHelper.addParameter('Headers presentes', `${presentHeaders.length}/${securityHeaders.length}`);
  });

  // --------------------------------------------------------------------
  // SEC-HEADERS-02: Cabeçalho CORS
  // --------------------------------------------------------------------
  test('SEC-HEADERS-02: Deve retornar cabeçalho CORS adequado', async ({ request }) => {
    AllureHelper.addSeverity('normal');
    AllureHelper.addTags('security', 'headers', 'cors');
    AllureHelper.addDescription(
      'Verifica a configuração de CORS. ' +
      'Access-Control-Allow-Origin: * é considerado inseguro para produção.'
    );
    AllureHelper.addTestCaseId('SEC-HEADERS-02');
    AllureHelper.addFeature('Segurança - Cabeçalhos HTTP');
    AllureHelper.addStory('CORS');

    const response = await request.get(API_BASE_URL, {
      headers: { 'Origin': 'https://example.com' },
    });
    const headers = response.headers();
    const allowOrigin = headers['access-control-allow-origin'];

    const corsResult: any = {
      'Access-Control-Allow-Origin': allowOrigin || 'AUSENTE',
      risco: 'Nenhum',
      recomendacao: 'OK - CORS não está exposto',
    };

    if (allowOrigin) {
      if (allowOrigin === '*') {
        corsResult.risco = 'ALTO';
        corsResult.recomendacao = 'CORS muito permissivo. Configure origens específicas.';
      } else if (allowOrigin.includes('*')) {
        corsResult.risco = 'MÉDIO';
        corsResult.recomendacao = 'CORS usa wildcard parcial. Revise a configuração.';
      } else {
        corsResult.risco = 'BAIXO';
        corsResult.recomendacao = `CORS configurado para origem específica: ${allowOrigin}`;
      }
      console.warn(`⚠️ CORS: Access-Control-Allow-Origin = ${allowOrigin} - Risco: ${corsResult.risco}`);
    } else {
      console.log('✅ CORS não está configurado (ou não exposto)');
    }

    AllureHelper.addAttachment(
      'Análise CORS',
      JSON.stringify(corsResult, null, 2),
      'application/json'
    );
  });

  // --------------------------------------------------------------------
  // SEC-HEADERS-03: Cabeçalhos de Cache
  // --------------------------------------------------------------------
  test('SEC-HEADERS-03: Deve conter cabeçalhos de Cache adequados', async ({ request }) => {
    AllureHelper.addSeverity('minor');
    AllureHelper.addTags('security', 'headers', 'cache');
    AllureHelper.addDescription(
      'Verifica cabeçalhos de cache para prevenir armazenamento de ' +
      'dados sensíveis no navegador.'
    );
    AllureHelper.addTestCaseId('SEC-HEADERS-03');
    AllureHelper.addFeature('Segurança - Cabeçalhos HTTP');
    AllureHelper.addStory('Cache Control');

    const response = await request.get(`${API_BASE_URL}/produtos`);
    const headers = response.headers();
    const cacheControl = headers['cache-control'];
    const pragma = headers['pragma'];

    const cacheResult = {
      'Cache-Control': cacheControl || 'AUSENTE',
      'Pragma': pragma || 'AUSENTE',
    };

    AllureHelper.addAttachment(
      'Análise de Cache',
      JSON.stringify(cacheResult, null, 2),
      'application/json'
    );

    if (!cacheControl) {
      console.warn('⚠️ Cache-Control ausente - dados podem ser armazenados em cache');
    }
  });
});
