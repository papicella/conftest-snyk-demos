FROM node:lts-bullseye as base

# To-Do: 
# 1. Multi-Stage to reduce size.
# 2. Change mext config to export as static.
# 3. Deployment template for Kubernetes.
# 4. End-to-end demo for Code through k8s for snyk evidence graph

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY . .
RUN \
  if [ -f yarn.lock ]; then yarn --frozen-lockfile; \
  elif [ -f package-lock.json ]; then npm ci; \
  elif [ -f pnpm-lock.yaml ]; then yarn global add pnpm && pnpm i --frozen-lockfile; \
  else echo "Lockfile not found." && exit 1; \
  fi

# Ensuring we  do not bring in env files
RUN rm -rf .env .env.local .env.development .env.*

EXPOSE 3000

ENV PORT 3000

# This runs in development mode
CMD ["yarn", "dev"]