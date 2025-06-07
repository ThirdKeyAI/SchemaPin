/**
 * Tests for interactive key pinning functionality.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert';
import {
    InteractivePinningManager,
    CallbackInteractiveHandler,
    PromptType,
    UserDecision,
    KeyInfo,
    PromptContext
} from '../src/interactive.js';
import { KeyPinning, PinningMode, PinningPolicy } from '../src/pinning.js';
import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';

// Mock function helper
function createMockFunction() {
    const calls = [];
    const fn = (...args) => {
        calls.push(args);
        return fn._returnValue;
    };
    fn.calls = calls;
    fn.mockResolvedValue = (value) => { fn._returnValue = Promise.resolve(value); };
    fn.mockReturnValue = (value) => { fn._returnValue = value; };
    return fn;
}

describe('InteractivePinningManager', () => {
    let mockHandler;
    let manager;
    const testToolId = 'test-tool';
    const testDomain = 'example.com';
    const testPublicKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtest...\n-----END PUBLIC KEY-----';
    const testDeveloperName = 'Test Developer';

    beforeEach(() => {
        mockHandler = {
            promptUser: createMockFunction(),
            displayKeyInfo: createMockFunction(),
            displaySecurityWarning: createMockFunction()
        };
        manager = new InteractivePinningManager(mockHandler);
    });

    test('createKeyInfo creates KeyInfo object', () => {
        const keyInfo = manager.createKeyInfo(
            testPublicKeyPem,
            testDomain,
            testDeveloperName
        );

        assert(keyInfo instanceof KeyInfo);
        assert.strictEqual(keyInfo.domain, testDomain);
        assert.strictEqual(keyInfo.developerName, testDeveloperName);
        assert(keyInfo.fingerprint.startsWith('sha256:'));
    });

    test('promptFirstTimeKey calls handler with correct context', async () => {
        mockHandler.promptUser.mockResolvedValue(UserDecision.ACCEPT);

        const decision = await manager.promptFirstTimeKey(
            testToolId,
            testDomain,
            testPublicKeyPem,
            { developer_name: testDeveloperName }
        );

        assert.strictEqual(decision, UserDecision.ACCEPT);
        assert.strictEqual(mockHandler.promptUser.calls.length, 1);

        const callArgs = mockHandler.promptUser.calls[0][0];
        assert.strictEqual(callArgs.promptType, PromptType.FIRST_TIME_KEY);
        assert.strictEqual(callArgs.toolId, testToolId);
        assert.strictEqual(callArgs.domain, testDomain);
    });

    test('promptKeyChange calls handler with current and new keys', async () => {
        const newKeyPem = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnew...\n-----END PUBLIC KEY-----';
        mockHandler.promptUser.mockResolvedValue(UserDecision.REJECT);

        const decision = await manager.promptKeyChange(
            testToolId,
            testDomain,
            testPublicKeyPem,
            newKeyPem,
            { developer_name: testDeveloperName }
        );

        assert.strictEqual(decision, UserDecision.REJECT);
        assert.strictEqual(mockHandler.promptUser.calls.length, 1);

        const callArgs = mockHandler.promptUser.calls[0][0];
        assert.strictEqual(callArgs.promptType, PromptType.KEY_CHANGE);
        assert(callArgs.currentKey);
        assert(callArgs.newKey);
    });

    test('promptRevokedKey marks key as revoked', async () => {
        mockHandler.promptUser.mockResolvedValue(UserDecision.REJECT);

        const decision = await manager.promptRevokedKey(
            testToolId,
            testDomain,
            testPublicKeyPem,
            { developer_name: testDeveloperName }
        );

        assert.strictEqual(decision, UserDecision.REJECT);
        assert.strictEqual(mockHandler.promptUser.calls.length, 1);

        const callArgs = mockHandler.promptUser.calls[0][0];
        assert.strictEqual(callArgs.promptType, PromptType.REVOKED_KEY);
        assert.strictEqual(callArgs.currentKey.isRevoked, true);
    });
});

describe('CallbackInteractiveHandler', () => {
    test('callback handler calls provided function', async () => {
        const mockCallback = createMockFunction();
        mockCallback.mockResolvedValue(UserDecision.ACCEPT);
        const handler = new CallbackInteractiveHandler(mockCallback);

        const context = new PromptContext({
            promptType: PromptType.FIRST_TIME_KEY,
            toolId: 'test-tool',
            domain: 'example.com'
        });

        const decision = await handler.promptUser(context);

        assert.strictEqual(decision, UserDecision.ACCEPT);
        assert.strictEqual(mockCallback.calls.length, 1);
        assert.strictEqual(mockCallback.calls[0][0], context);
    });

    test('displayKeyInfo formats key information', () => {
        const handler = new CallbackInteractiveHandler(createMockFunction());

        const keyInfo = new KeyInfo({
            fingerprint: 'sha256:abc123',
            pemData: 'test-pem',
            domain: 'example.com',
            developerName: 'Test Dev'
        });

        const displayText = handler.displayKeyInfo(keyInfo);

        assert(displayText.includes('sha256:abc123'));
        assert(displayText.includes('example.com'));
        assert(displayText.includes('Test Dev'));
    });
});

describe('KeyPinning Interactive Functionality', () => {
    test('automatic mode pins without prompts', async () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const pinning = new KeyPinning(dbPath, PinningMode.AUTOMATIC);

            const result = await pinning.interactivePinKey(
                'test-tool',
                '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
                'example.com',
                'Test Developer'
            );

            assert.strictEqual(result, true);
            assert.strictEqual(pinning.isKeyPinned('test-tool'), true);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });

    test('interactive mode with first-time key acceptance', async () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const mockHandler = {
                promptUser: createMockFunction(),
                displayKeyInfo: createMockFunction(),
                displaySecurityWarning: createMockFunction()
            };
            
            const pinning = new KeyPinning(dbPath, PinningMode.INTERACTIVE, mockHandler);
            
            // Mock the interactive manager
            const mockPrompt = createMockFunction();
            mockPrompt.mockResolvedValue(UserDecision.ACCEPT);
            pinning.interactiveManager.promptFirstTimeKey = mockPrompt;

            const result = await pinning.interactivePinKey(
                'test-tool',
                '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
                'example.com',
                'Test Developer'
            );

            assert.strictEqual(result, true);
            assert.strictEqual(pinning.isKeyPinned('test-tool'), true);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });

    test('domain policy always trust', async () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const pinning = new KeyPinning(dbPath, PinningMode.INTERACTIVE);
            
            // Set always trust policy
            pinning.setDomainPolicy('example.com', PinningPolicy.ALWAYS_TRUST);

            const result = await pinning.interactivePinKey(
                'test-tool',
                '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
                'example.com',
                'Test Developer'
            );

            assert.strictEqual(result, true);
            assert.strictEqual(pinning.isKeyPinned('test-tool'), true);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });

    test('domain policy never trust', async () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const pinning = new KeyPinning(dbPath, PinningMode.INTERACTIVE);
            
            // Set never trust policy
            pinning.setDomainPolicy('example.com', PinningPolicy.NEVER_TRUST);

            const result = await pinning.interactivePinKey(
                'test-tool',
                '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
                'example.com',
                'Test Developer'
            );

            assert.strictEqual(result, false);
            assert.strictEqual(pinning.isKeyPinned('test-tool'), false);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });

    test('strict mode rejects key changes', async () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const pinning = new KeyPinning(dbPath, PinningMode.STRICT);
            
            // Pin initial key
            const initialKey = '-----BEGIN PUBLIC KEY-----\ninitial\n-----END PUBLIC KEY-----';
            pinning.pinKey('test-tool', initialKey, 'example.com', 'Test Developer');

            const newKey = '-----BEGIN PUBLIC KEY-----\nnew\n-----END PUBLIC KEY-----';
            const result = await pinning.interactivePinKey(
                'test-tool',
                newKey,
                'example.com',
                'Test Developer'
            );

            assert.strictEqual(result, false);
            assert.strictEqual(pinning.getPinnedKey('test-tool'), initialKey);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });
});

describe('Domain Policy Management', () => {
    test('setDomainPolicy and getDomainPolicy work correctly', () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const pinning = new KeyPinning(dbPath);

            assert.strictEqual(pinning.getDomainPolicy('example.com'), PinningPolicy.DEFAULT);

            pinning.setDomainPolicy('example.com', PinningPolicy.ALWAYS_TRUST);
            assert.strictEqual(pinning.getDomainPolicy('example.com'), PinningPolicy.ALWAYS_TRUST);

            pinning.setDomainPolicy('example.com', PinningPolicy.NEVER_TRUST);
            assert.strictEqual(pinning.getDomainPolicy('example.com'), PinningPolicy.NEVER_TRUST);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });

    test('domain policies persist across instances', () => {
        const tempDir = join(tmpdir(), `schemapin-test-${Date.now()}`);
        mkdirSync(tempDir, { recursive: true });
        const dbPath = join(tempDir, 'test_pinning.json');
        
        try {
            const pinning1 = new KeyPinning(dbPath);
            pinning1.setDomainPolicy('example.com', PinningPolicy.ALWAYS_TRUST);

            const pinning2 = new KeyPinning(dbPath);
            assert.strictEqual(pinning2.getDomainPolicy('example.com'), PinningPolicy.ALWAYS_TRUST);
        } finally {
            if (existsSync(dbPath)) unlinkSync(dbPath);
            try { require('fs').rmSync(tempDir, { recursive: true }); } catch (e) {}
        }
    });
});