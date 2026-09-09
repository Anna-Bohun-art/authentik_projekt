import { describe, expect, it } from 'vitest';
import {
  InsufficientScopeError,
  InvalidTokenError,
  ServiceFault,
  UnauthorizedError,
  UserNotFoundError,
} from '../src/soap/faults.js';

describe('ServiceFault -> SOAP 1.1 fault mapping', () => {
  it('maps a 4xx fault to a Client actor with a coded detail', () => {
    const fault = new UnauthorizedError('no token').toNodeSoapFault();
    expect(fault.Fault.faultcode).toBe('SOAP-ENV:Client');
    expect(fault.Fault.faultstring).toBe('unauthorized: no token');
    expect(fault.Fault.detail.ServiceFault).toEqual({
      code: 'unauthorized',
      message: 'no token',
    });
    expect(fault.Fault.statusCode).toBe(401);
  });

  it('maps a 5xx fault to a Server actor', () => {
    const fault = new ServiceFault('internal_error', 'boom', 500).toNodeSoapFault();
    expect(fault.Fault.faultcode).toBe('SOAP-ENV:Server');
    expect(fault.Fault.statusCode).toBe(500);
  });

  it('carries the required scope in an insufficient_scope fault', () => {
    const fault = new InsufficientScopeError('user.write').toNodeSoapFault();
    expect(fault.Fault.detail.ServiceFault.code).toBe('insufficient_scope');
    expect(fault.Fault.faultstring).toContain('user.write');
    expect(fault.Fault.statusCode).toBe(403);
  });

  it('assigns stable codes and HTTP statuses per error type', () => {
    expect(new InvalidTokenError().code).toBe('invalid_token');
    expect(new InvalidTokenError().httpStatus).toBe(401);
    expect(new UserNotFoundError('x').code).toBe('not_found');
    expect(new UserNotFoundError('x').httpStatus).toBe(404);
  });
});
