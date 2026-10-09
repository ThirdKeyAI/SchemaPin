/**
 * Verifier-side lineage store for schema-version binding (spec section 18.4).
 *
 * `verifyChain` compares two signature documents the caller already holds. A
 * verifier that wants protection against rollback and forks needs to remember
 * the latest accepted `skill_hash` for each tool and insist that every new
 * signature descends from it. `LineageStore` is that memory.
 *
 * Only feed it signature documents that `verifySkillOffline` has already
 * accepted, and only `schemapin_version >= "1.4"` documents: their
 * `skill_hash`, `previous_hash` and `schema_version` are covered by the
 * signature, which is what makes the chain meaningful. Legacy 1.3 documents
 * are refused.
 */

/**
 * Thrown when a signature does not descend from the recorded lineage.
 */
export class LineageError extends Error {
    constructor(message) {
        super(message);
        this.name = 'LineageError';
    }
}

const SEMVER_RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/;

function versionKey(version) {
    const m = SEMVER_RE.exec(version);
    return m ? [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)] : null;
}

function isLegacyVersion(version) {
    const m = /^(\d+)\.(\d+)$/.exec(typeof version === 'string' ? version : '');
    return m !== null && (Number(m[1]) < 1 || (Number(m[1]) === 1 && Number(m[2]) < 4));
}

/**
 * Return true when `current` sorts strictly after `previous`.
 *
 * Numeric `major.minor.patch` prefixes compare numerically (`1.10.0` >
 * `1.9.0`); when either side is not semver-like the comparison falls back to
 * a plain string comparison, which still rejects reuse of the same value.
 *
 * @param {string} previous
 * @param {string} current
 * @returns {boolean}
 */
export function versionIncreases(previous, current) {
    const p = versionKey(previous);
    const c = versionKey(current);
    if (p && c && (p[0] !== c[0] || p[1] !== c[1] || p[2] !== c[2])) {
        for (let i = 0; i < 3; i++) {
            if (c[i] !== p[i]) {
                return c[i] > p[i];
            }
        }
    }
    return current > previous;
}

/**
 * In-memory `latest_known_hash` store keyed by `toolId@domain`.
 */
export class LineageStore {
    constructor() {
        this._latest = new Map();
    }

    _key(toolId, domain) {
        return `${toolId}@${domain}`;
    }

    /**
     * @param {string} toolId
     * @param {string} domain
     * @returns {{ skill_hash: string, schema_version: string|null }|null}
     */
    get(toolId, domain) {
        return this._latest.get(this._key(toolId, domain)) ?? null;
    }

    /**
     * Pre-seed the latest accepted state (for example from a trusted manifest).
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {string} skillHash
     * @param {string|null} [schemaVersion=null]
     */
    seed(toolId, domain, skillHash, schemaVersion = null) {
        this._latest.set(this._key(toolId, domain), { skill_hash: skillHash, schema_version: schemaVersion });
    }

    /**
     * Check `signatureData` against the lineage and advance on success.
     *
     * @param {string} toolId
     * @param {string} domain
     * @param {Object} signatureData - an already-verified v1.4 signature document
     * @param {boolean} [requireChain=true]
     * @returns {'first_use'|'unchanged'|'advanced'}
     * @throws {LineageError}
     */
    checkAndAdvance(toolId, domain, signatureData, requireChain = true) {
        if (isLegacyVersion(signatureData.schemapin_version)) {
            throw new LineageError('legacy 1.3 signature documents carry an unsigned skill_hash and cannot anchor a lineage');
        }
        const skillHash = signatureData.skill_hash;
        if (typeof skillHash !== 'string' || skillHash === '') {
            throw new LineageError('signature document has no skill_hash');
        }
        const schemaVersion = typeof signatureData.schema_version === 'string' ? signatureData.schema_version : null;
        const key = this._key(toolId, domain);
        const record = this._latest.get(key);
        if (!record) {
            this._latest.set(key, { skill_hash: skillHash, schema_version: schemaVersion });
            return 'first_use';
        }
        if (record.skill_hash === skillHash) {
            return 'unchanged';
        }
        const previousHash = signatureData.previous_hash;
        if (previousHash === null || previousHash === undefined) {
            if (requireChain) {
                throw new LineageError(`signature for ${key} has no previous_hash; expected a descendant of ${record.skill_hash}`);
            }
        } else if (previousHash !== record.skill_hash) {
            throw new LineageError(`previous_hash ${previousHash} does not match the latest accepted skill_hash ${record.skill_hash} for ${key} (fork or rollback)`);
        }
        if (schemaVersion !== null && record.schema_version !== null && !versionIncreases(record.schema_version, schemaVersion)) {
            throw new LineageError(`schema_version ${JSON.stringify(schemaVersion)} does not increase over ${JSON.stringify(record.schema_version)} for ${key}`);
        }
        this._latest.set(key, { skill_hash: skillHash, schema_version: schemaVersion });
        return 'advanced';
    }

    /** @returns {string} */
    toJSON() {
        return JSON.stringify(Object.fromEntries(this._latest));
    }

    /**
     * @param {string} jsonStr
     * @returns {LineageStore}
     */
    static fromJSON(jsonStr) {
        const data = JSON.parse(jsonStr);
        if (data === null || typeof data !== 'object' || Array.isArray(data)) {
            throw new Error('lineage store JSON must be an object');
        }
        const store = new LineageStore();
        for (const [key, value] of Object.entries(data)) {
            if (!value || typeof value.skill_hash !== 'string') {
                throw new Error('lineage store entries must carry a skill_hash');
            }
            store._latest.set(key, { skill_hash: value.skill_hash, schema_version: value.schema_version ?? null });
        }
        return store;
    }
}
