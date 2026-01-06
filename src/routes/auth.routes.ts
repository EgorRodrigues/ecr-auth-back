import { FastifyInstance } from 'fastify';
import { register, login, refresh, me } from '../controllers/auth.controller';

export async function authRoutes(app: FastifyInstance) {
  app.post('/register', register);
  app.post('/login', login);
  app.patch('/token/refresh', refresh);
  app.get('/me', me);
}
