import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { app } from '../app';
import { prisma } from '../lib/prisma';
import { comparePassword, hashPassword } from '../utils/hash';

// Mock do Prisma
vi.mock('../lib/prisma', () => ({
  prisma: {
    user: {
      findUnique: vi.fn(),
      create: vi.fn(),
    },
    refreshToken: {
      create: vi.fn(),
      findUnique: vi.fn(),
      delete: vi.fn(),
    },
  },
}));

// Mock do Hash
vi.mock('../utils/hash', () => ({
  hashPassword: vi.fn(),
  comparePassword: vi.fn(),
}));

describe('Auth Controller', () => {
  beforeAll(async () => {
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('POST /register', () => {
    it('should register a new user', async () => {
      (prisma.user.findUnique as any).mockResolvedValue(null);
      (hashPassword as any).mockResolvedValue('hashed_password');
      (prisma.user.create as any).mockResolvedValue({
        id: 'user-id',
        name: 'Test User',
        email: 'test@example.com',
        password: 'hashed_password',
      });

      const response = await request(app.server)
        .post('/register')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(201);
      expect(prisma.user.create).toHaveBeenCalled();
    });

    it('should not register if user already exists', async () => {
      (prisma.user.findUnique as any).mockResolvedValue({ id: 'existing-id' });

      const response = await request(app.server)
        .post('/register')
        .send({
          name: 'Test User',
          email: 'existing@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(409);
    });
  });

  describe('POST /login', () => {
    it('should login successfully and return tokens in body', async () => {
      const user = {
        id: 'user-id',
        email: 'test@example.com',
        password: 'hashed_password',
      };

      (prisma.user.findUnique as any).mockResolvedValue(user);
      (comparePassword as any).mockResolvedValue(true);
      (prisma.refreshToken.create as any).mockResolvedValue({
        id: 'refresh-id',
        token: 'refresh-token',
        userId: 'user-id',
      });

      const response = await request(app.server)
        .post('/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('refreshToken');
    });

    it('should fail with invalid credentials', async () => {
      (prisma.user.findUnique as any).mockResolvedValue(null);

      const response = await request(app.server)
        .post('/login')
        .send({
          email: 'wrong@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(400);
    });
  });

  describe('GET /me', () => {
    it('should return user profile when authenticated via header', async () => {
      const user = {
        id: 'user-id',
        email: 'test@example.com',
        name: 'Test User',
        createdAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(user);

      // Gerar um token válido usando a instância do app
      const token = app.jwt.sign({ sub: user.id });

      const response = await request(app.server)
        .get('/me')
        .set('Authorization', `Bearer ${token}`)
        .send();

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          createdAt: user.createdAt.toISOString(),
        }
      });
    });

    it('should return 401 when missing header', async () => {
      const response = await request(app.server)
        .get('/me')
        .send();

      expect(response.status).toBe(401);
    });
  });

  describe('PATCH /token/refresh', () => {
    it('should refresh token successfully via body', async () => {
      const user = {
        id: 'user-id',
      };
      
      // Criar um refresh token válido
      const refreshToken = app.jwt.sign({ sub: user.id, expiresIn: '7d' });

      (prisma.refreshToken.findUnique as any).mockResolvedValue({
        id: 'refresh-id',
        token: refreshToken,
        userId: user.id,
      });

      (prisma.refreshToken.delete as any).mockResolvedValue({});
      (prisma.refreshToken.create as any).mockResolvedValue({});

      const response = await request(app.server)
        .patch('/token/refresh')
        .send({
          refreshToken
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('refreshToken');
    });

    it('should fail with invalid refresh token', async () => {
      const response = await request(app.server)
        .patch('/token/refresh')
        .send({
          refreshToken: 'invalid-token'
        });

      expect(response.status).toBe(401);
    });
  });
});
