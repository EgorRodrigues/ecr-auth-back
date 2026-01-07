import fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import fastifyOAuth2 from '@fastify/oauth2';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { authRoutes } from './routes/auth.routes';

export const app = fastify({
  logger: true,
  disableRequestLogging: false,
});

app.setValidatorCompiler(validatorCompiler);
app.setSerializerCompiler(serializerCompiler);

app.register(fastifyCookie);

app.addHook('onRequest', async (request) => {
  (request as any)._startAt = process.hrtime.bigint();
});

app.addHook('onResponse', async (request, reply) => {
  const start = (request as any)._startAt as bigint | undefined;
  let ms: number | undefined;
  if (typeof start === 'bigint') {
    ms = Number((process.hrtime.bigint() - start) / BigInt(1e6));
  }
  const line = `${request.method} ${request.url} -> ${reply.statusCode}${ms !== undefined ? ` ${ms}ms` : ''}`;
  if ((request as any).log) {
    request.log.info(
      {
        method: request.method,
        url: request.url,
        statusCode: reply.statusCode,
        responseTimeMs: ms,
        requestId: request.id,
      },
      'http'
    );
  } else {
    console.log(line);
  }
});

app.register(fastifyCors, {
  origin: true, // Permitir todas as origens (ajuste conforme necessário para produção)
  credentials: true, // Permitir envio de cookies
});

app.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'secret',
  cookie: {
    cookieName: 'refreshToken',
    signed: false,
  },
  sign: {
    expiresIn: '10m',
  },
});

app.register(fastifyOAuth2, {
  name: 'googleOAuth2',
  credentials: {
    client: {
      id: process.env.GOOGLE_CLIENT_ID || '',
      secret: process.env.GOOGLE_CLIENT_SECRET || '',
    },
    auth: {
      authorizeHost: 'https://accounts.google.com',
      authorizePath: '/o/oauth2/v2/auth',
      tokenHost: 'https://oauth2.googleapis.com',
      tokenPath: '/token',
    },
  },
  callbackUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3333/auth/google/callback',
  scope: ['openid', 'email', 'profile'],
});

app.register(authRoutes);
