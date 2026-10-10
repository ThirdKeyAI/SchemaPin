/**
 * Shared domain-name validation.
 *
 * Every place that turns a domain string into something security-relevant --
 * a .well-known URL, a pin-store key, a local file path, a DNS lookup name --
 * MUST pass it through {@link validateDomain} first. The grammar is the
 * RFC 1123 hostname grammar, restricted further so the value cannot be
 * confused with a URL, a path, an IP literal or an IDN U-label:
 *
 * - ASCII only (internationalized names must be given as punycode A-labels)
 * - at least two labels, each 1-63 characters of [a-z0-9-] that neither
 *   start nor end with "-"
 * - total length at most 253 characters
 * - the last label is not purely numeric (rejects IPv4 literals)
 * - no scheme, path, port, userinfo or trailing dot
 *
 * The returned value is lowercased so pin keys and file names are consistent
 * regardless of how the caller spelled the domain.
 */

/** Maximum total length of a domain name. */
export const MAX_DOMAIN_LENGTH = 253;

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Thrown when a string is not an acceptable SchemaPin domain.
 */
export class InvalidDomainError extends Error {
    constructor(message) {
        super(message);
        this.name = 'InvalidDomainError';
    }
}

/**
 * Validate `domain` and return its normalized (lowercase) form.
 *
 * @param {string} domain
 * @returns {string}
 * @throws {InvalidDomainError}
 */
export function validateDomain(domain) {
    if (typeof domain !== 'string' || domain.length === 0) {
        throw new InvalidDomainError('domain must be a non-empty string');
    }
    if (domain.length > MAX_DOMAIN_LENGTH) {
        throw new InvalidDomainError(`domain exceeds ${MAX_DOMAIN_LENGTH} characters`);
    }
    // eslint-disable-next-line no-control-regex
    if (!/^[\x00-\x7f]*$/.test(domain)) {
        throw new InvalidDomainError('domain must be ASCII; encode internationalized names as punycode');
    }
    const normalized = domain.toLowerCase();
    const labels = normalized.split('.');
    if (labels.length < 2) {
        throw new InvalidDomainError(`domain ${JSON.stringify(domain)} must contain at least two labels`);
    }
    for (const label of labels) {
        if (!LABEL_RE.test(label)) {
            throw new InvalidDomainError(`domain ${JSON.stringify(domain)} has an invalid label ${JSON.stringify(label)}`);
        }
    }
    if (/^[0-9]+$/.test(labels[labels.length - 1])) {
        throw new InvalidDomainError(`domain ${JSON.stringify(domain)} looks like an IP literal`);
    }
    return normalized;
}

/**
 * @param {string} domain
 * @returns {boolean} true when {@link validateDomain} would accept `domain`
 */
export function isValidDomain(domain) {
    try {
        validateDomain(domain);
        return true;
    } catch {
        return false;
    }
}
