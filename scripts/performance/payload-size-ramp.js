/**
 * Payloads progressivos
 *
 * Vai subindo o tamanho do campo descricao de 10KB ate 2MB
 * e mede onde o tempo de resposta dobra. Isso acha o "ponto de joelho"
 * da API, onde ela comeca a sofrer silenciosamente.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 5,
  duration: '1m',
};

const BASE_URL = 'https://serverest.dev';

// Tamanhos pra testar (em caracteres)
const sizes = [10 * 1024, 100 * 1024, 500 * 1024, 1024 * 1024, 2 * 1024 * 1024];
let currentSizeIndex = 0;

export default function () {
  const size = sizes[currentSizeIndex % sizes.length];
  const desc = 'X'.repeat(size);

  const payload = JSON.stringify({
    nome: `Produto ${size} bytes`,
    preco: 100,
    descricao: desc,
    quantidade: 10,
  });

  const res = http.post(`${BASE_URL}/produtos`, payload, {
    headers: { 'Content-Type': 'application/json' },
  });

  check(res, {
    'criacao com payload grande': (r) => r.status === 201 || r.status === 400 || r.status === 413,
  });

  if (res.status === 201) {
    const id = res.json()._id;
    // limpa
    http.del(`${BASE_URL}/produtos/${id}`);
  }

  console.log(`[PAYLOAD] ${size} bytes -> ${res.timings.duration}ms`);

  currentSizeIndex++;
  sleep(2);
}