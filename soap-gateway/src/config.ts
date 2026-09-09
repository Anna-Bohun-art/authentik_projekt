import { z } from 'zod';

/**
 * Configuration is validated once at startup. An invalid environment fails fast
 * with a readable message instead of surfacing as a confusing runtime error
 * halfway through the first request.
 */
const Schema = z.object({
  GATEWAY_PORT: z.coerce.number().int().positive().default(8000),

  // OAuth 2.0 / OIDC resource-server settings. Point these at the authentik
  // OAuth2 provider that fronts this service (see docs/authentik-setup.md).
  // The defaults let `npm run dev` start with no .env; they are only actually
  // contacted when a request presents a token to verify.
  OIDC_ISSUER: z.string().url().default('http://localhost:9000/application/o/soap-gateway/'),
  OIDC_JWKS_URI: z
    .string()
    .url()
    .default('http://localhost:9000/application/o/soap-gateway/jwks/'),
  OIDC_AUDIENCE: z.string().min(1).default('soap-gateway'),

  // Where the demo user directory lives. "memory" needs no database; it is the
  // default so the service runs with zero setup. docker-compose sets "postgres".
  USER_DIRECTORY: z.enum(['postgres', 'memory']).default('memory'),
  PGHOST: z.string().default('localhost'),
  PGPORT: z.coerce.number().int().positive().default(5432),
  PGUSER: z.string().default('authentik'),
  PGPASSWORD: z.string().optional(),
  PGDATABASE: z.string().default('soapdemo'),

  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
    .default('info'),
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
