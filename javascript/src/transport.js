/**
 * Hardened HTTP fetch helpers shared by discovery and revocation.
 *
 * Every outbound request made by this package goes through {@link fetchJson}:
 *
 * - https:// only -- plaintext URLs are refused before any socket is opened
 * - redirects are never followed (`redirect: 'error'`)
 * - the response body is capped at {@link MAX_RESPONSE_BYTES}
 * - the abort timer covers the whole exchange, including reading the body
 */

/** Maximum accepted response body size (bytes). */
export const MAX_RESPONSE_BYTES = 64 * 1024;

/** Default timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 10000;

/**
 * Thrown for any transport-level failure (scheme, redirect, size, network).
 */
export class TransportError extends Error {
    constructor(message) {
        super(message);
        this.name = 'TransportError';
    }
}

/**
 * Return `url` unchanged if it is an absolute https:// URL without userinfo.
 *
 * @param {string} url
 * @returns {string}
 * @throws {TransportError}
 */
export function requireHttps(url) {
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw new TransportError(`invalid URL: ${JSON.stringify(url)}`);
    }
    if (parsed.protocol !== 'https:' || !parsed.hostname) {
        throw new TransportError(`only https:// URLs are permitted: ${JSON.stringify(url)}`);
    }
    if (parsed.username || parsed.password) {
        throw new TransportError(`userinfo is not permitted in URLs: ${JSON.stringify(url)}`);
    }
    return url;
}

/**
 * Read a response body with a byte cap.
 *
 * @param {Response} response
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
async function readCapped(response, maxBytes) {
    const reader = response.body?.getReader?.();
    if (!reader) {
        const buf = Buffer.from(await response.arrayBuffer());
        if (buf.length > maxBytes) {
            throw new TransportError(`response exceeds ${maxBytes} bytes`);
        }
        return buf;
    }
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        total += value.length;
        if (total > maxBytes) {
            await reader.cancel().catch(() => {});
            throw new TransportError(`response exceeds ${maxBytes} bytes`);
        }
        chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
}

/**
 * GET `url` and decode the JSON body under the hardening rules above.
 *
 * @param {string} url
 * @param {number} [timeout=DEFAULT_TIMEOUT_MS] - milliseconds
 * @param {number} [maxBytes=MAX_RESPONSE_BYTES]
 * @returns {Promise<*>} parsed JSON
 * @throws {TransportError}
 */
export async function fetchJson(url, timeout = DEFAULT_TIMEOUT_MS, maxBytes = MAX_RESPONSE_BYTES) {
    requireHttps(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        let response;
        try {
            response = await fetch(url, {
                signal: controller.signal,
                redirect: 'error',
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'SchemaPin'
                }
            });
        } catch (e) {
            throw new TransportError(`request failed for ${url}: ${e.message}`);
        }
        if (response.status !== 200) {
            throw new TransportError(`HTTP ${response.status} fetching ${url}`);
        }
        const body = await readCapped(response, maxBytes);
        try {
            return JSON.parse(body.toString('utf8'));
        } catch (e) {
            throw new TransportError(`invalid JSON from ${url}: ${e.message}`);
        }
    } finally {
        clearTimeout(timer);
    }
}
