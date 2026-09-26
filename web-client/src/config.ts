import { z } from 'zod';

/**
 * Same fail-fast pattern as soap-gateway/src/config.ts: an invalid or
 * incomplete .env should stop the process at startup with a readable
 * message, not surface as a confusing error on the first /login.
 */
const Schema = z.object({
  PORT: z.coerce.number().int().positive().default(3000),

  ISSUER: z.string().url().default('http://localhost:9001/application/o/soap-gateway/'),
  AUTHORIZATION_ENDPOINT: z
    .string()
    .url()
    .default('http://localhost:9001/application/o/authorize/'),
  TOKEN_ENDPOINT: z.string().url().default('http://localhost:9001/application/o/token/'),
  JWKS_URI: z.string().url().default('http://localhost:9001/application/o/soap-gateway/jwks/'),
  CLIENT_ID: z.string().min(1).default('soap-gateway'),
  // No default: this is a confidential client, the secret must come from .env.
  CLIENT_SECRET: z.string().min(1, 'copy the client secret from authentik into .env'),
  REDIRECT_URI: z.string().url().default('http://localhost:3000/callback'),

  GATEWAY_WSDL: z.string().url().default('http://localhost:8000/soap?wsdl'),
  GATEWAY_ENDPOINT: z.string().url().default('http://localhost:8000/soap'),
});

export type AppConfig = z.infer<typeof Schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = Schema.safeParse(env);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${details}`);
  }
  return parsed.data;
}
