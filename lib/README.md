# QuantumShield

Post-quantum cryptography toolkit for AI systems. Part of the QuantaMrkt marketplace.

## Installation

```bash
pip install quantumshield
```

For development:

```bash
pip install quantumshield[dev]
```

## Usage

### Create an Agent Identity

```python
from quantumshield.identity import AgentIdentity

agent = AgentIdentity.create("my-agent", capabilities=["sign", "verify"])
print(agent.did)
```

### Sign a Model

```python
from quantumshield.registry import ModelManifest

manifest = ModelManifest.from_model("./my-model/")
manifest.sign(agent.signing_keypair)
manifest.save("manifest.json")
```

### Analyze a Codebase for PQC Migration

```python
from quantumshield.migrator import MigrationAgent

migrator = MigrationAgent()
report = migrator.analyze("./src/")
print(f"Found {len(report.vulnerabilities)} vulnerabilities in {report.files_scanned} files")
```

## CLI

```bash
# Create an agent identity
quantumshield agent create my-agent

# Analyze code for quantum-vulnerable crypto
quantumshield migrate analyze ./src/

# Sign a model directory
quantumshield registry sign ./my-model/
```

## License

Apache-2.0
