/**
 * Domain errors that map onto SOAP 1.1 Faults.
 *
 * The wire contract (see wsdl/userService.wsdl) declares a `ServiceFault`
 * detail element carrying a stable machine-readable `code` plus a human
 * `message`, so callers can branch on `code` without string-matching.
 */

export type ServiceFaultCode =
  | 'unauthorized' // no usable credential presented
  | 'invalid_token' // credential present but failed verification
  | 'insufficient_scope' // token valid but missing the required scope
  | 'not_found' // the referenced resource does not exist
  | 'bad_request' // malformed input
  | 'internal_error';

/** SOAP 1.1 fault payload understood by node-soap's server. */
export interface NodeSoapFault {
  Fault: {
    faultcode: string;
    faultstring: string;
    detail: {
      ServiceFault: { code: ServiceFaultCode; message: string };
    };
    statusCode: number;
  };
}

export class ServiceFault extends Error {
  constructor(
    readonly code: ServiceFaultCode,
    message: string,
    readonly httpStatus: number,
  ) {
    super(message);
    this.name = 'ServiceFault';
  }

  /** `Client` faults are the caller's fault; `Server` faults are ours. */
  private faultActor(): 'SOAP-ENV:Client' | 'SOAP-ENV:Server' {
    return this.httpStatus >= 500 ? 'SOAP-ENV:Server' : 'SOAP-ENV:Client';
  }

  toNodeSoapFault(): NodeSoapFault {
    return {
      Fault: {
        faultcode: this.faultActor(),
        faultstring: `${this.code}: ${this.message}`,
        detail: { ServiceFault: { code: this.code, message: this.message } },
        statusCode: this.httpStatus,
      },
    };
  }
}

export class UnauthorizedError extends ServiceFault {
  constructor(message = 'no access token presented') {
    super('unauthorized', message, 401);
  }
}

export class InvalidTokenError extends ServiceFault {
  constructor(message = 'access token verification failed') {
    super('invalid_token', message, 401);
  }
}

export class InsufficientScopeError extends ServiceFault {
  constructor(requiredScope: string) {
    super(
      'insufficient_scope',
      `the presented token does not grant the required scope "${requiredScope}"`,
      403,
    );
  }
}

export class UserNotFoundError extends ServiceFault {
  constructor(username: string) {
    super('not_found', `user "${username}" does not exist`, 404);
  }
}

export class BadRequestError extends ServiceFault {
  constructor(message: string) {
    super('bad_request', message, 400);
  }
}
