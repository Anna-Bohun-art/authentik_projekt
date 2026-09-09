import pino, { type Logger } from 'pino';

export type { Logger };

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: { service: 'soap-gateway' },
    redact: {
      // Never let a raw token reach the logs.
      paths: ['token', '*.token', 'authorization', '*.authorization'],
      censor: '[redacted]',
    },
  });
}
