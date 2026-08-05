/**
 * Carrinhos abandonados
 *
 * Cria uma enxurrada de carrinhos e nunca finaliza compra.
 * Depois mede se a listagem de carrinhos fica lenta.
 * Isso aqui acontece em toda Black Friday de verdade.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '20s', target: 20 },
    { duration: '40s', target: 20 },
    { duration: '20s', target: 0 },
  ],
};

const BASE_URL = 'https://serverest.dev';

let adminToken = null;

export function setup() {
  // Autentica como admin pra listar carrinhos depois
  const loginRes = http.post(`${BASE_URL}/login`, JSON.stringify({
    email: 'fulano@qa.com',
    password: 'teste',
  }), { headers: { 'Content-Type': 'application/json' } });
  if (loginRes.status === 200) {
    adminToken = loginRes.json().authorization;
  }
  return { adminToken };
}

export default function (data) {
  // Usuario comum criando carrinho com produto aleatorio
  const email = `cart_${__VU}_${__ITER}@qa.com`;
  const password = '123456';

  // Cria usuario (ignora se ja existe)
  http.post(`${BASE_URL}/usuarios`, JSON.stringify({
    nome: `User ${__VU}`,
    email,
    password,
    administrador: 'false',
  }), { headers: { 'Content-Type': 'application/json' } });

  // Login
  const loginRes = http.post(`${BASE_URL}/login`, JSON.stringify({ email, password }), {
    headers: { 'Content-Type': 'application/json' },
  });
  if (loginRes.status !== 200) {
    sleep(2);
    return;
  }
  const token = loginRes.json().authorization;

  // Busca produto
  const prodRes = http.get(`${BASE_URL}/produtos`);
  const produtos = prodRes.json().produtos || prodRes.json();
  if (Array.isArray(produtos) && produtos.length > 0) {
    const produto = produtos[Math.floor(Math.random() * produtos.length)];
    // Cria carrinho
    http.post(`${BASE_URL}/carrinhos`, JSON.stringify({
      produtos: [{ idProduto: produto._id, quantidade: 1 }],
    }), {
      headers: { 'Content-Type': 'application/json', 'Authorization': token },
    });
  }

  sleep(3);
}

export function teardown(data) {
  // Lista carrinhos com token admin pra ver quantos ficaram
  if (data.adminToken) {
    const res = http.get(`${BASE_URL}/carrinhos`, {
      headers: { 'Authorization': data.adminToken },
    });
    console.log(`[CARRINHOS] Total de carrinhos apos teste: ${res.status}`);
  }
}