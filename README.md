# API Key Manager

[![CI](https://github.com/Retsumdk/api-key-manager/workflows/CI/badge.svg)](https://github.com/Retsumdk/api-key-manager/actions)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Rotating API key management with usage tracking. Securely rotate API keys with automatic key rotation, usage monitoring, and quota management.

## Features

- **Automatic Rotation** — Schedule key rotation based on time or usage thresholds
- **Usage Tracking** — Monitor API calls per key with analytics
- **Quota Management** — Set per-key usage limits with alerts
- **Secure Storage** — Keys encrypted at rest with env-based secret management
- **Multi-Provider Support** — Works with any API provider (OpenAI, Anthropic, etc.)

## Installation

```bash
git clone https://github.com/Retsumdk/api-key-manager.git
cd api-key-manager
npm install
```

## Quick Start

```bash
npm run build
npm start
```

## Configuration

Create `config.json` for custom settings:

```json
{
  "rotationIntervalDays": 90,
  "maxUsagePerKey": 100000,
  "alertThreshold": 0.8
}
```

## Related Repos

- [json-schema-validator](https://github.com/Retsumdk/json-schema-validator) — JSON Schema validation middleware
- [audit-logger](https://github.com/Retsumdk/audit-logger) — Immutable audit trail for compliance
- [rate-limiter-middleware](https://github.com/Retsumdk/rate-limiter-middleware) — API rate limiting

## License

MIT License — see [LICENSE](LICENSE)
