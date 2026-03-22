# AID-MCP Profile

**Integration point:** MCP tool server middleware

See Section 8.1 of the [AID Protocol Specification](../aid-protocol-v1.md) for the full profile definition.

## Quick Start

```typescript
import { withAidTrust } from '@aidprotocol/mcp-trust';

const server = new McpServer({ name: 'my-api' });

const aid = withAidTrust(server, {
  providerDid: 'did:key:zMyDid...',
  minTrustScore: 40,
  formulaVersion: '1.0.0',
  failMode: 'closed'
});

server.tool('get-data', { query: z.string() }, async (params, extra) => {
  const trust = aid.getCallerTrust(extra);
  return { content: [{ type: 'text', text: 'result' }] };
});
```

## npm Package

`@aidprotocol/mcp-trust` — [npm](https://www.npmjs.com/package/@aidprotocol/mcp-trust)
