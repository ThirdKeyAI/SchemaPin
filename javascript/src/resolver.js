/**
 * Discovery resolver abstraction for SchemaPin.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { PublicKeyDiscovery } from './discovery.js';
import { fetchRevocationDocument } from './revocation.js';
import { findDiscovery, findRevocation, parseTrustBundle } from './bundle.js';

/**
 * Abstract base class for discovery resolution.
 */
export class SchemaResolver {
    /**
     * Resolve a well-known discovery document for a domain.
     *
     * @param {string} domain
     * @returns {Promise<Object|null>}
     */
    async resolveDiscovery(domain) {
        throw new Error('resolveDiscovery not implemented');
    }

    /**
     * Resolve a revocation document for a domain.
     *
     * @param {string} domain
     * @param {Object} discovery
     * @returns {Promise<Object|null>}
     */
    async resolveRevocation(domain, discovery) {
        throw new Error('resolveRevocation not implemented');
    }
}

/**
 * Resolves discovery via standard .well-known HTTPS endpoints.
 */
export class WellKnownResolver extends SchemaResolver {
    constructor(timeout = 10000) {
        super();
        this._timeout = timeout;
    }

    async resolveDiscovery(domain) {
        try {
            return await PublicKeyDiscovery.fetchWellKnown(domain, this._timeout);
        } catch {
            return null;
        }
    }

    async resolveRevocation(domain, discovery) {
        const endpoint = discovery?.revocation_endpoint;
        if (!endpoint) return null;
        return await fetchRevocationDocument(endpoint, this._timeout);
    }
}

/**
 * Resolves discovery from local JSON files.
 */
export class LocalFileResolver extends SchemaResolver {
    constructor(discoveryDir, revocationDir = null) {
        super();
        this._discoveryDir = discoveryDir;
        this._revocationDir = revocationDir;
    }

    async resolveDiscovery(domain) {
        try {
            const path = join(this._discoveryDir, `${domain}.json`);
            const data = readFileSync(path, 'utf-8');
            return JSON.parse(data);
        } catch {
            return null;
        }
    }

    async resolveRevocation(domain, discovery) {
        if (!this._revocationDir) return null;
        try {
            const path = join(this._revocationDir, `${domain}.revocations.json`);
            const data = readFileSync(path, 'utf-8');
            return JSON.parse(data);
        } catch {
            return null;
        }
    }
}

/**
 * Resolves discovery from an in-memory trust bundle.
 */
export class TrustBundleResolver extends SchemaResolver {
    constructor(bundle) {
        super();
        this._bundle = bundle;
    }

    static fromJson(jsonStr) {
        const bundle = parseTrustBundle(jsonStr);
        return new TrustBundleResolver(bundle);
    }

    async resolveDiscovery(domain) {
        return findDiscovery(this._bundle, domain);
    }

    async resolveRevocation(domain, discovery) {
        return findRevocation(this._bundle, domain);
    }
}

/**
 * Tries multiple resolvers in order, returning the first success.
 */
export class ChainResolver extends SchemaResolver {
    constructor(resolvers) {
        super();
        this._resolvers = resolvers;
    }

    async resolveDiscovery(domain) {
        for (const resolver of this._resolvers) {
            const result = await resolver.resolveDiscovery(domain);
            if (result !== null) return result;
        }
        return null;
    }

    async resolveRevocation(domain, discovery) {
        for (const resolver of this._resolvers) {
            const result = await resolver.resolveRevocation(domain, discovery);
            if (result !== null) return result;
        }
        return null;
    }
}
