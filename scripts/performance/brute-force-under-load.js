/**
 * Forca bruta sob carga normal
 *
 * Enquanto usuarios normais fazem compras, 10 atacantes tentam
 * logar com senha errada. Isso testa se a falta de rate limiting
 * (que ja sabemos que existe) piora a experiencia dos legitimos.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    legit_users: {
      executor: 'constant-vus',
      vus: 30,
      duration: '1m',
      exec: 'legitUser',
    },
    attackers: {
      executor: 'constant-vus',
      vus: 10,
      duration: '1m',
      exec: 'attacker',
    },
  },
  thresholds: {
    'http_req_duration{scenario:legit_users}': ['p(95)<4000'],
  },
};

const BASE_URL = 'https://serverest.dev';

// Usuarios legitimos navegando e comprando
export function legitUser() {
  const res = http.get(`${BASE_URL}/produtos`);
  check(res, { 'produtos ok': (r) => r.status === 200 });

  // Tenta criar carrinho (precisa de autenticacao)
  const email = `legit_${__VU}_${__ITER}@qa.com`;
  http.post(`${BASE_URL}/usuarios`, JSON.stringify({
    nome: 'Cliente Real',
    email,
    password: 'senha123',
    administrador: 'false',
  }), { headers: { 'Content-Type': 'application/json' } });

  const loginRes = http.post(`${BASE_URL}/login`, JSON.stringify({ email, password: 'senha123' }), {
    headers: { 'Content-Type': 'application/json' },
  });

  if (loginRes.status === 200) {
    const token = loginRes.json().authorization;
    http.get(`${BASE_URL}/carrinhos`, {
      headers: { 'Authorization': token },
    });
  }

  sleep(3);
}

// Atacantes tentando forca bruta
export function attacker() {
  const passwords = ['123456', 'admin', 'senha', 'password', 'teste'];
  const password = passwords[Math.floor(Math.random() * passwords.length)];

  const res = http.post(`${BASE_URL}/login`, JSON.stringify({
    email: 'admin@email.com',
    password,
  }), { headers: { 'Content-Type': 'application/json' } });

  check(res, {
    'tentativa de login': (r) => r.status === 401 || r.status === 200,
  });

  // sem sleep = martelada continua
}