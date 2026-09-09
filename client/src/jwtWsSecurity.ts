const WSSE_NS =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
const BASE64_ENCODING_TYPE =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
const JWT_VALUE_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

/**
 * node-soap client "security" strategy that carries an OAuth 2.0 access token
 * *inside* the SOAP envelope as a WS-Security BinarySecurityToken, rather than
 * on the HTTP Authorization header. Useful when the message is relayed through
 * an intermediary that would drop HTTP headers.
 *
 * node-soap injects the return value of `toXML()` into <soap:Header> — but only
 * for a strategy that does NOT define `postProcess`, so this class omits it.
 */
export class JwtWSSecurity {
  private readonly encodedToken: string;

  constructor(jwt: string) {
    this.encodedToken = Buffer.from(jwt, 'utf8').toString('base64');
  }

  addOptions(): void {}
  addHeaders(): void {}

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
