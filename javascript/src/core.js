/**
 * Core SchemaPin functionality for schema canonicalization and hashing.
 */

import { createHash } from 'crypto';

/**
 * Core SchemaPin operations for schema canonicalization and hashing.
 */
export class SchemaPinCore {
    /**
     * Convert a schema to canonical string format per SchemaPin specification.
     * 
     * Process:
     * 1. UTF-8 encoding
     * 2. Remove insignificant whitespace
     * 3. Sort keys lexicographically (recursive)
     * 4. Strict JSON serialization
     * 
     * @param {Object} schema - Tool schema as object
     * @returns {string} Canonical string representation
     */
    static canonicalizeSchema(schema) {
        // Recursively sort keys and use compact separators (no whitespace)
        const sortKeys = (obj) => {
            if (obj === null || typeof obj !== 'object') {
                return obj;
            }
            if (Array.isArray(obj)) {
                return obj.map(sortKeys);
            }
            const sorted = {};
            Object.keys(obj).sort().forEach(key => {
                sorted[key] = sortKeys(obj[key]);
            });
            return sorted;
        };
        
        return JSON.stringify(sortKeys(schema), null, 0);
    }

    /**
     * Hash canonical schema string using SHA-256.
     * 
     * @param {string} canonical - Canonical schema string
     * @returns {Buffer} SHA-256 hash bytes
     */
    static hashCanonical(canonical) {
        return createHash('sha256').update(canonical, 'utf8').digest();
    }

    /**
     * Convenience method to canonicalize and hash schema in one step.
     * 
     * @param {Object} schema - Tool schema as object
     * @returns {Buffer} SHA-256 hash of canonical schema
     */
    static canonicalizeAndHash(schema) {
        const canonical = this.canonicalizeSchema(schema);
        return this.hashCanonical(canonical);
    }
}