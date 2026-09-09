import type { IServices, ISoapServiceMethod } from 'soap';
import { authenticate, type AuthContext } from '../auth/authenticate.js';
import { assertScope } from '../auth/scopes.js';
import type { TokenVerifier } from '../auth/tokens.js';
import type { UserDirectory } from '../directory/types.js';
import type { Logger } from '../logger.js';
import { BadRequestError, ServiceFault, UserNotFoundError } from './faults.js';

export interface HandlerDeps {
  verifier: TokenVerifier;
  directory: UserDirectory;
  log: Logger;
}

/** Scope required by each SOAP operation. */
const REQUIRED_SCOPE = {
  GetUserDisplayName: 'user.read',
  ListGroups: 'user.read',
  DeactivateUser: 'user.write',
} as const;

// node-soap passes (args, callback, soapHeaders, req). We only use the async
// return form, so `callback` is intentionally ignored.
type SoapArgs = Record<string, unknown>;
type SoapReq = { headers?: Record<string, string | string[] | undefined> };

function requireString(args: SoapArgs, field: string): string {
  const value = args[field];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new BadRequestError(`"${field}" is required`);
  }
  return value.trim();
}

export function buildService(deps: HandlerDeps): IServices {
  /** Authenticate + authorize, then hand the operation an AuthContext. */
  function guarded(
    operation: keyof typeof REQUIRED_SCOPE,
    run: (ctx: AuthContext, args: SoapArgs) => Promise<unknown>,
  ): ISoapServiceMethod {
    return async (args: SoapArgs, _callback: unknown, soapHeaders: unknown, req: SoapReq) => {
      try {
        const ctx = await authenticate({ verifier: deps.verifier, req, soapHeaders });
        assertScope(ctx.claims, REQUIRED_SCOPE[operation]);
        deps.log.info(
          { operation, subject: ctx.subject, transport: ctx.transport },
          'authorized SOAP call',
        );
        return await run(ctx, args);
      } catch (err) {
        if (err instanceof ServiceFault) {
          deps.log.warn({ operation, code: err.code }, err.message);
          // node-soap recognises a thrown object with a `Fault` property.
          throw err.toNodeSoapFault();
        }
        deps.log.error({ operation, err }, 'unhandled error in SOAP operation');
        throw new ServiceFault('internal_error', 'internal error', 500).toNodeSoapFault();
      }
    };
  }

  return {
    UserService: {
      UserServicePort: {
        GetUserDisplayName: guarded('GetUserDisplayName', async (_ctx, args) => {
          const username = requireString(args, 'username');
          const user = await deps.directory.getUser(username);
          if (!user) throw new UserNotFoundError(username);
          return { displayName: user.displayName };
        }),

        ListGroups: guarded('ListGroups', async (_ctx, args) => {
          const username = requireString(args, 'username');
          const user = await deps.directory.getUser(username);
          if (!user) throw new UserNotFoundError(username);
          const groups = await deps.directory.listGroups(username);
          return { group: groups };
        }),

        DeactivateUser: guarded('DeactivateUser', async (ctx, args) => {
          const username = requireString(args, 'username');
          const ok = await deps.directory.deactivateUser(username);
          if (!ok) throw new UserNotFoundError(username);
          return { status: 'DEACTIVATED', performedBy: ctx.subject };
        }),
      },
    },
  };
}
