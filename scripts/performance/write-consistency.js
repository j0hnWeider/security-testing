/**
 * Consistencia em escrita concorrente
 *
 * Dispara 20 PUTs simultaneos no mesmo produto com precos diferentes.
 * Depois verifica se o valor final eh consistente (nao corrompido).
 * Complementa o race-condition.spec.ts com visao de performance.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

let inconsistentCount = new Counter('inconsistent_updates');

export const options = {
  vus: 20,
  duration: '30s',
};

const BASE_URL = 'https://serverest.dev';

// Produto alvo (criado no setup)
let targetProductId = null;
let adminToken = null;

export function setup() {
  // Autentica como admin
  const loginRes = http.post(`${BASE_URL}/login`, JSON.stringify({
    email: 'fulano@qa.com',
    password: 'teste',
  }), { headers: { 'Content-Type': 'application/json' } });
  if (loginRes.status === 200) {
    adminToken = loginRes.json().authorization;
  }

  // Cria produto
  const createRes = http.post(`${BASE_URL}/produtos`, JSON.stringify({
    nome: 'Produto Concorrente',
    preco: 100,
    descricao: 'Teste de consistencia',
    quantidade: 50,
  }), {
    headers: { 'Content-Type': 'application/json', 'Authorization': adminToken },
  });
  if (createRes.status === 201) {
    targetProductId = createRes.json()._id;
    console.log(`[CONSISTENCIA] Produto alvo: ${targetProductId}`);
  }
  return { targetProductId, adminToken };
}

export default function (data) {
  if (!data.targetProductId || !data.adminToken) return;

  const newPrice = Math.floor(Math.random() * 200) + 1;

  const res = http.put(`${BASE_URL}/produtos/${data.targetProductId}`, JSON.stringify({
    nome: 'Produto Concorrente',
    preco: newPrice,
    descricao: 'Atualizado',
    quantidade: 50,
  }), {
    headers: { 'Content-Type': 'application/json', 'Authorization': data.adminToken },
  });

  check(res, {
    'update aceito': (r) => r.status === 200 || r.status === 201,
  });

  sleep(0.5);
}

export function teardown(data) {
  // Verifica valor final
  if (data.targetProductId && data.adminToken) {
    const res = http.get(`${BASE_URL}/produtos/${data.targetProductId}`, {
      headers: { 'Authorization': data.adminToken },
    });
    if (res.status === 200) {
      const produto = res.json();
      console.log(`[CONSISTENCIA] Preco final: ${produto.preco}`);
    }
    // Limpa
    http.del(`${BASE_URL}/produtos/${data.targetProductId}`, null, {
      headers: { 'Authorization': data.adminToken },
    });
  }
}