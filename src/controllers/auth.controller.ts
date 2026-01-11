import { FastifyReply, FastifyRequest } from 'fastify';
import { prisma } from '../lib/prisma';
import { hashPassword, comparePassword } from '../utils/hash';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'crypto';

export async function register(request: FastifyRequest, reply: FastifyReply) {
  const registerBodySchema = z.object({
    name: z.string(),
    email: z.string().email(),
    password: z.string().min(6),
  });

  const { name, email, password } = registerBodySchema.parse(request.body);

  const userExists = await prisma.user.findUnique({
    where: { email },
  });

  if (userExists) {
    return reply.status(409).send({ message: 'User already exists.' });
  }

  const password_hash = await hashPassword(password);

  await prisma.user.create({
    data: {
      name,
      email,
      password: password_hash,
    },
  });

  return reply.status(201).send();
}

export async function login(request: FastifyRequest, reply: FastifyReply) {
  const loginBodySchema = z.object({
    email: z.string().email(),
    password: z.string(),
  });

  const { email, password } = loginBodySchema.parse(request.body);

  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    return reply.status(400).send({ message: 'Invalid credentials.' });
  }

  const doesPasswordMatch = await comparePassword(password, user.password);

  if (!doesPasswordMatch) {
    return reply.status(400).send({ message: 'Invalid credentials.' });
  }

  const token = await reply.jwtSign(
    {},
    {
      sign: {
        sub: user.id,
      },
    }
  );

  const refreshToken = await reply.jwtSign(
    {},
    {
      sign: {
        sub: user.id,
        expiresIn: '7d',
      },
    }
  );

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 dias
    }
  });

  return reply
    .status(200)
    .send({
      token,
      refreshToken,
    });
}

export async function googleAuthRedirect(request: FastifyRequest, reply: FastifyReply) {
  const app = request.server as FastifyInstance & { googleOAuth2?: any };
  if (!app.googleOAuth2) {
    return reply.status(500).send({ message: 'OAuth plugin not configured.' });
  }
  const url = await app.googleOAuth2.generateAuthorizationUri(request, reply);
  return reply.redirect(url);
}

export async function googleAuthCallback(request: FastifyRequest, reply: FastifyReply) {
  const app = request.server as FastifyInstance & { googleOAuth2?: any };
  if (!app.googleOAuth2) {
    return reply.status(500).send({ message: 'OAuth plugin not configured.' });
  }
  const tokenResponse = await app.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);
  const accessToken = tokenResponse?.token?.access_token as string | undefined;
  const idToken = tokenResponse?.token?.id_token as string | undefined;
  let email: string | undefined;
  let name: string | undefined;
  if (accessToken) {
    const res = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (res.ok) {
      const data: any = await res.json();
      email = data?.email as string | undefined;
      name = data?.name as string | undefined;
    }
  }
  if (!email && idToken) {
    try {
      const [, payloadB64] = idToken.split('.');
      const payloadJson = Buffer.from(payloadB64, 'base64').toString('utf-8');
      const payload = JSON.parse(payloadJson);
      email = payload.email;
      name = payload.name;
    } catch {}
  }
  if (!email) {
    return reply.status(400).send({ message: 'Email not available from provider.' });
  }
  let user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    const password_hash = await hashPassword(randomUUID());
    user = await prisma.user.create({ data: { email, name: name || '', password: password_hash } });
  }
  const token = await reply.jwtSign({}, { sign: { sub: user.id } });
  const refreshToken = await reply.jwtSign({}, { sign: { sub: user.id, expiresIn: '7d' } });
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    }
  });
  const successRedirect = process.env.OAUTH_SUCCESS_REDIRECT_URL;
  if (successRedirect) {
    return reply.redirect(`${successRedirect}?token=${encodeURIComponent(token)}&refreshToken=${encodeURIComponent(refreshToken)}`);
  }
  return reply.status(200).send({ token, refreshToken });
}

export async function refresh(request: FastifyRequest, reply: FastifyReply) {
  const refreshBodySchema = z.object({
    refreshToken: z.string(),
  });

  const { refreshToken } = refreshBodySchema.parse(request.body);

  let sub: string;
  try {
    const decoded = request.server.jwt.verify<{ sub: string }>(refreshToken);
    sub = decoded.sub;
  } catch (err) {
    return reply.status(401).send({ message: 'Invalid refresh token.' });
  }
  
  const storedToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken }
  });

  if (!storedToken) {
       return reply.status(401).send({ message: 'Invalid refresh token.' });
  }

  const token = await reply.jwtSign(
    {},
    {
      sign: {
        sub,
      },
    }
  );

  const newRefreshToken = await reply.jwtSign(
    {},
    {
      sign: {
        sub,
        expiresIn: '7d',
      },
    }
  );
  
  await prisma.refreshToken.delete({
      where: { id: storedToken.id }
  });

  await prisma.refreshToken.create({
      data: {
          token: newRefreshToken,
          userId: sub,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      }
  });

  return reply
    .status(200)
    .send({
      token,
      refreshToken: newRefreshToken,
    });
}

export async function me(request: FastifyRequest, reply: FastifyReply) {
    const user = await prisma.user.findUnique({
        where: { id: request.user.sub },
        select: {
            id: true,
            email: true,
            name: true,
            createdAt: true
        }
    });

    return reply.send({ user });
}
