import fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import fastifyOAuth2 from '@fastify/oauth2';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { authRoutes } from './routes/auth.routes';

export const app = fastify();

app.setValidatorCompiler(validatorCompiler);
app.setSerializerCompiler(serializerCompiler);

app.register(fastifyCookie);

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
