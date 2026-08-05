/**
 * Black Friday - 80% do trafego num unico produto
 *
 * Simula promocao relampago: a maioria dos usuarios acessando
 * o mesmo produto. Se nao tiver cache, o banco derrete.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '10s', target: 50 },
    { duration: '1m', target: 50 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'],
  },
};

const BASE_URL = 'https://serverest.dev';

// Pega uma lista inicial pra descobrir IDs de produtos
let hotProductId = null;

export function setup() {
  const res = http.get(`${BASE_URL}/produtos`);
  const body = res.json();
  const produtos = body.produtos || body;
  if (Array.isArray(produtos) && produtos.length > 0) {
    hotProductId = produtos[0]._id;
    console.log(`[BLACK-FRIDAY] Produto em foco: ${hotProductId}`);
  }
  return { hotProductId };
}

export default function (data) {
  const id = data.hotProductId;
  if (!id) {
    // sem produto, navega normal
    http.get(`${BASE_URL}/produtos`);
    sleep(2);
    return;
  }

  // 80% de chance de acessar o produto quente
  if (Math.random() < 0.8) {
    const res = http.get(`${BASE_URL}/produtos/${id}`);
    check(res, { 'produto acessivel': (r) => r.status === 200 });
  } else {
    http.get(`${BASE_URL}/produtos`);
  }

  sleep(1);
}