import { FastifyInstance } from 'fastify';
import { register, login, refresh, me, googleAuthRedirect, googleAuthCallback } from '../controllers/auth.controller';

export async function authRoutes(app: FastifyInstance) {
  app.post('/register', register);
  app.post('/login', login);
  app.get('/auth/google', googleAuthRedirect);
  app.get('/auth/google/callback', googleAuthCallback);
  app.patch('/token/refresh', refresh);
  app.get('/me', me);
}
