# Stage 1: Build
FROM node:20-slim AS builder

WORKDIR /app

# Copiar arquivos de dependências
COPY package*.json ./
COPY prisma ./prisma/

# Instalar todas as dependências (incluindo devDependencies para o build)
RUN npm ci

# Copiar código fonte
COPY tsconfig.json ./
COPY src ./src

# Build da aplicação
RUN npm run build

# Stage 2: Production
FROM node:20-slim

WORKDIR /app

# Copiar arquivos de dependências
COPY package*.json ./
COPY prisma ./prisma/

# Instalar OpenSSL para correta detecção de versão pela Prisma
RUN apt-get update -y && apt-get install -y openssl

# Instalar apenas dependências de produção
RUN npm ci --only=production

# Gerar o cliente Prisma
RUN npx prisma generate

# Copiar build do estágio anterior
COPY --from=builder /app/dist ./dist

EXPOSE 8080

CMD ["npm", "start"]
