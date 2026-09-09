/**
 * Two ways an OAuth 2.0 access token can reach a SOAP service:
 *
 *  1. HTTP transport   ->  `Authorization: Bearer <jwt>`   (modern default)
 *  2. Message level     ->  <wsse:Security><wsse:BinarySecurityToken>
 *
 * (2) exists because SOAP messages routed through intermediaries (an ESB, a
 * message queue) frequently lose their HTTP headers, so the security context
 * has to travel *inside* the envelope. The token itself is identical; only the
 * carrier differs. See docs/architecture.md for the trade-offs.
 */

export const WSSE_NS =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
export const JWT_VALUE_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
export const BASE64_ENCODING_TYPE =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

const BEARER_RE = /^Bearer\s+(.+)$/i;

interface HttpLike {
  headers?: Record<string, string | string[] | undefined>;
}

/** Pull a bearer token out of the HTTP `Authorization` header, if present. */
export function extractHttpBearer(req: HttpLike | undefined): string | undefined {
  const header = req?.headers?.['authorization'] ?? req?.headers?.['Authorization'];
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return undefined;
  const match = BEARER_RE.exec(value.trim());
  return match?.[1]?.trim() || undefined;
}

// node-soap hands parsed SOAP headers back as a plain object. Namespace
// prefixes may or may not be stripped depending on parser options, so match
// on the local name.
function findByLocalName(obj: unknown, localName: string): unknown {
  if (!obj || typeof obj !== 'object') return undefined;
  const target = localName.toLowerCase();
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const local = key.includes(':') ? key.slice(key.indexOf(':') + 1) : key;
    if (local.toLowerCase() === target) return value;
  }
  return undefined;
}

function readElementText(node: unknown): string | undefined {
  if (typeof node === 'string') return node;
  if (node && typeof node === 'object') {
    const rec = node as Record<string, unknown>;
    const text = rec['$value'] ?? rec['_'] ?? rec['#text'];
    if (typeof text === 'string') return text;
  }
  return undefined;
}

function readAttributes(node: unknown): Record<string, string> {
  if (node && typeof node === 'object') {
    const rec = node as Record<string, unknown>;
    const attrs = (rec['attributes'] ?? rec['$attributes']) as
      | Record<string, string>
      | undefined;
    if (attrs && typeof attrs === 'object') return attrs;
  }
  return {};
}

/**
 * Extract the JWT from a parsed `<wsse:Security>` SOAP header.
 * The token is Base64-decoded when the element advertises the WS-Security
 * Base64Binary encoding; a bare (un-encoded) JWT is also tolerated.
 */
export function extractWsSecurityToken(soapHeaders: unknown): string | undefined {
  const security = findByLocalName(soapHeaders, 'Security');
  const bst = findByLocalName(security, 'BinarySecurityToken');
  if (bst === undefined) return undefined;

  const rawText = readElementText(bst)?.trim();
  if (!rawText) return undefined;

  const attributes = readAttributes(bst);
  const encoding = attributes['EncodingType'] ?? attributes['encodingType'];

  if (encoding === BASE64_ENCODING_TYPE) {
    const decoded = Buffer.from(rawText, 'base64').toString('utf8').trim();
    return decoded || undefined;
  }
  return rawText;
}
