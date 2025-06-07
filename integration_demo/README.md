# SchemaPin Integration Demo

This directory contains a comprehensive demonstration of SchemaPin's cross-language integration capabilities, showcasing Python and JavaScript implementations working together.

## Overview

The integration demo demonstrates:
- Cross-language schema signing and verification
- Automatic and interactive key pinning scenarios
- Key revocation handling
- Server-based key discovery
- Batch processing workflows

## Demo Scenarios

### Scenario 1: Python Signs, JavaScript Verifies (Auto-pinning)
- Python tool developer signs schemas
- JavaScript client verifies with automatic key pinning
- Demonstrates seamless cross-language compatibility

### Scenario 2: JavaScript Signs, Python Verifies (Interactive)
- JavaScript tool developer signs schemas
- Python client verifies with interactive pinning prompts
- Shows user-controlled security decisions

### Scenario 3: Key Rotation with Revocation
- Demonstrates key rotation workflow
- Shows revocation list management
- Tests cross-language revocation checking

### Scenario 4: Cross-language Batch Processing
- Bulk schema signing and verification
- Performance testing across implementations
- Compatibility validation

### Scenario 5: Server-based Discovery
- Uses .well-known server for key discovery
- Tests multiple developer endpoints
- Validates CORS and security features

## Setup

### Prerequisites
- Python 3.8+ with SchemaPin package installed
- Node.js 16+ with SchemaPin package installed
- Optional: Docker for server deployment

### Installation

1. Install Python dependencies:
```bash
cd ../python
pip install -e .
```

2. Install JavaScript dependencies:
```bash
npm install
```

3. Generate test keys:
```bash
python demo_scenario.py --setup
```

## Running Demos

### Quick Start
Run all scenarios:
```bash
python cross_language_test.py
```

### Individual Scenarios
```bash
# Scenario 1: Python → JavaScript
python demo_scenario.py --scenario 1

# Scenario 2: JavaScript → Python  
node demo_scenario.js --scenario 2

# Scenario 3: Key revocation
python demo_scenario.py --scenario 3

# Scenario 4: Batch processing
python demo_scenario.py --scenario 4

# Scenario 5: Server discovery
python demo_scenario.py --scenario 5
```

### Interactive Mode
```bash
python demo_scenario.py --interactive
```

## Server Integration

Start the .well-known server:
```bash
cd ../server
python well_known_server.py
```

The server provides:
- Multiple developer endpoints
- Key revocation management
- CORS support for browser clients
- REST API for key operations

## Test Data

The demo uses sample schemas in [`sample_schemas/`](sample_schemas/) including:
- MCP tool schemas
- API endpoint definitions
- Complex nested structures
- Edge case scenarios

## Performance Testing

Run performance benchmarks:
```bash
python cross_language_test.py --performance
```

## Security Validation

Validate security features:
```bash
python cross_language_test.py --security
```

## Troubleshooting

### Common Issues

1. **Key generation fails**
   - Ensure cryptography libraries are installed
   - Check file permissions in output directory

2. **Cross-language verification fails**
   - Verify both implementations use same schema canonicalization
   - Check signature format compatibility

3. **Server connection issues**
   - Ensure server is running on correct port
   - Check firewall and network settings

### Debug Mode
```bash
python demo_scenario.py --debug
```

## File Structure

```
integration_demo/
├── README.md                 # This file
├── demo_scenario.py          # Python demo script
├── demo_scenario.js          # JavaScript demo script
├── cross_language_test.py    # Automated testing
├── package.json              # Node.js dependencies
├── sample_schemas/           # Test schemas
│   ├── mcp_tool.json
│   ├── api_endpoint.json
│   └── complex_nested.json
└── test_data/               # Generated during demos
    ├── keys/
    ├── signed_schemas/
    └── verification_results/
```

## API Compatibility

Both Python and JavaScript implementations provide identical APIs:

### Signing Workflow
```python
# Python
workflow = SchemaSigningWorkflow(private_key_pem)
signature = workflow.sign_schema(schema)
```

```javascript
// JavaScript
const workflow = new SchemaSigningWorkflow(privateKeyPem);
const signature = workflow.signSchema(schema);
```

### Verification Workflow
```python
# Python
workflow = SchemaVerificationWorkflow()
result = workflow.verify_schema(schema, signature, tool_id, domain)
```

```javascript
// JavaScript
const workflow = new SchemaVerificationWorkflow();
const result = await workflow.verifySchema(schema, signature, toolId, domain);
```

## Contributing

When adding new demo scenarios:
1. Update both Python and JavaScript implementations
2. Add corresponding test cases
3. Update documentation
4. Ensure cross-platform compatibility

## Security Considerations

- Demo keys are for testing only - never use in production
- Server runs in development mode - configure properly for production
- Interactive prompts demonstrate security UX patterns
- Revocation checking shows real-world security scenarios