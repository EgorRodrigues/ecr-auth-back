import { FastifyReply, FastifyRequest } from 'fastify';
import { prisma } from '../lib/prisma';
import { hashPassword, comparePassword } from '../utils/hash';
import { z } from 'zod';

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
    .setCookie('refreshToken', refreshToken, {
      path: '/',
      secure: false, // TODO: Mudar para true em prod (HTTPS)
      sameSite: true,
      httpOnly: true,
    })
    .status(200)
    .send({
      token,
    });
}

export async function refresh(request: FastifyRequest, reply: FastifyReply) {
  await request.jwtVerify({ onlyCookie: true });

  const { sub } = request.user;
  const refreshToken = request.cookies.refreshToken;

  if (!refreshToken) {
     return reply.status(401).send({ message: 'Unauthorized.' });
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
    .setCookie('refreshToken', newRefreshToken, {
      path: '/',
      secure: false, // TODO: true em prod
      sameSite: true,
      httpOnly: true,
    })
    .status(200)
    .send({
      token,
    });
}

export async function me(request: FastifyRequest, reply: FastifyReply) {
    await request.jwtVerify();

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
