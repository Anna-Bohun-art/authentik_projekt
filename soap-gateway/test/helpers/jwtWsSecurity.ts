import { WSSE_NS } from '../../src/auth/wsSecurity.js';

const BASE64_ENCODING_TYPE =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const JWT_VALUE_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

/**
 * A node-soap client "security" strategy that carries an OAuth 2.0 access token
 * inside the SOAP envelope as a WS-Security BinarySecurityToken, instead of on
 * the HTTP Authorization header. node-soap injects the `toXML()` output into
 * <soap:Header>.
 *
 * Note: node-soap only inserts `toXML()` into the header when the strategy has
 * *no* `postProcess` method (with `postProcess` present it expects that method
 * to splice the security into the full envelope itself). So this class
 * deliberately does not implement `postProcess`.
 */
export class JwtWSSecurity {
  private readonly encodedToken: string;

  constructor(jwt: string) {
    this.encodedToken = Buffer.from(jwt, 'utf8').toString('base64');
  }

  addOptions(): void {
    /* no HTTP-level options needed */
  }

  addHeaders(): void {
    /* no HTTP headers added — the token travels in the message */
  }

  toXML(): string {
    return (
      `<wsse:Security xmlns:wsse="${WSSE_NS}">` +
      `<wsse:BinarySecurityToken ValueType="${JWT_VALUE_TYPE}" ` +
      `EncodingType="${BASE64_ENCODING_TYPE}">` +
      this.encodedToken +
      `</wsse:BinarySecurityToken>` +
      `</wsse:Security>`
    );
  }
}
