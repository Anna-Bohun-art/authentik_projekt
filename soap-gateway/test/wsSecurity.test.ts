import { describe, expect, it } from 'vitest';
import {
  BASE64_ENCODING_TYPE,
  extractHttpBearer,
  extractWsSecurityToken,
} from '../src/auth/wsSecurity.js';

const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature';

describe('extractHttpBearer', () => {
  it('reads a lowercase authorization header', () => {
    expect(extractHttpBearer({ headers: { authorization: `Bearer ${JWT}` } })).toBe(JWT);
  });

  it('is case-insensitive on the scheme', () => {
    expect(extractHttpBearer({ headers: { authorization: `bearer ${JWT}` } })).toBe(JWT);
  });

  it('ignores a non-bearer scheme', () => {
    expect(extractHttpBearer({ headers: { authorization: 'Basic abc123' } })).toBeUndefined();
  });

  it('returns undefined when there is no header', () => {
    expect(extractHttpBearer({ headers: {} })).toBeUndefined();
    expect(extractHttpBearer(undefined)).toBeUndefined();
  });
});

describe('extractWsSecurityToken', () => {
  it('decodes a Base64-encoded BinarySecurityToken (node-soap parsed shape)', () => {
    const parsed = {
      Security: {
        BinarySecurityToken: {
          attributes: {
            ValueType: 'urn:ietf:params:oauth:token-type:jwt',
            EncodingType: BASE64_ENCODING_TYPE,
          },
          $value: Buffer.from(JWT, 'utf8').toString('base64'),
        },
      },
    };
    expect(extractWsSecurityToken(parsed)).toBe(JWT);
  });

  it('tolerates a namespace-prefixed key and a bare (un-encoded) token', () => {
    const parsed = {
      'wsse:Security': {
        'wsse:BinarySecurityToken': JWT,
      },
    };
    expect(extractWsSecurityToken(parsed)).toBe(JWT);
  });

  it('returns undefined when no security header is present', () => {
    expect(extractWsSecurityToken({})).toBeUndefined();
    expect(extractWsSecurityToken(undefined)).toBeUndefined();
  });
});
