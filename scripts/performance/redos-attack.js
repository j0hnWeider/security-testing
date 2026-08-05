/**
 * ReDoS sob carga
 *
 * Ideia: enviar payload que pode acionar backtracking em regex mal escrita
 * enquanto tem usuario normal navegando. Se a API tiver regex vulneravel,
 * o tempo de resposta dispara e o servidor vai pro chao.
 * Isso aqui derrubou Cloudflare em 2019, nao eh brincadeira.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '20s', target: 30 },  // 30 usuarios
    { duration: '1m', target: 30 },
    { duration: '20s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'],
  },
};

const BASE_URL = 'https://serverest.dev';

// Payloads com potencial de backtracking
const payloads = [
  'aaaaaaaaaaaaaaaaaaaa!',     // classico de regex mal feita
  'a?a?a?a?a?a?a?a?a?a?a?',   // alternancia forcada
  '***************',           // wildcard
];

export default function () {
  const payload = payloads[Math.floor(Math.random() * payloads.length)];

  // Usuario normal navegando
  const resNormal = http.get(`${BASE_URL}/produtos`);
  check(resNormal, { 'status 200': (r) => r.status === 200 });

  sleep(1);

  // Usuario malicioso fazendo busca com payload suspeito
  const resBusca = http.get(`${BASE_URL}/produtos?nome=${encodeURIComponent(payload)}`);
  check(resBusca, {
    'busca nao quebrou o servidor': (r) => r.status === 200 || r.status === 400,
  });

  sleep(2);
}