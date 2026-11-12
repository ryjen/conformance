import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer, type Server } from 'node:http';
import { once } from 'node:events';
import { AuthorizationCodeGrantScenario } from './authorization-code-grant';
import { startCallbackServer } from './auth/helpers/createCallbackServer';

vi.mock('./auth/helpers/createCallbackServer', () => ({
  startCallbackServer: vi.fn()
}));

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve) => server.close(() => resolve()))
      )
  );
  vi.clearAllMocks();
});

describe('authorization code replay over real HTTP', () => {
  it.each([
    { acceptReplay: false, expected: 'SUCCESS' },
    { acceptReplay: true, expected: 'FAILURE' }
  ])(
    'reports $expected when acceptReplay=$acceptReplay',
    async ({ acceptReplay, expected }) => {
      const requests: string[] = [];
      const server = createServer(async (req, res) => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(Buffer.from(chunk));
        requests.push(Buffer.concat(chunks).toString('utf8'));
        res.setHeader('content-type', 'application/json');
        if (requests.length === 2 && !acceptReplay) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'invalid_grant' }));
        } else {
          res.setHeader('cache-control', 'no-store');
          res.writeHead(200);
          res.end(
            JSON.stringify({ access_token: 'test-token', token_type: 'Bearer' })
          );
        }
      });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      servers.push(server);
      const address = server.address();
      if (!address || typeof address === 'string')
        throw new Error('No HTTP port');
      const base = `http://127.0.0.1:${address.port}`;
      const scenario = new AuthorizationCodeGrantScenario();
      vi.mocked(startCallbackServer).mockReturnValue({
        waitForCallback: async () =>
          `http://127.0.0.1:3000/callback?code=one-time-code&state=${(scenario as any).state}`,
        close: () => {}
      });
      const checks = await scenario.run(
        { url: base, clientId: 'test-client', port: 3000 },
        {
          'authorization-server-metadata-endpoint': {
            body: {
              issuer: base,
              authorization_endpoint: `${base}/authorize`,
              token_endpoint: `${base}/token`,
              token_endpoint_auth_methods_supported: ['none']
            }
          }
        }
      );
      expect(checks.map((check) => [check.id, check.status])).toEqual([
        ['authorization-code-grant', 'SUCCESS'],
        ['code-replay', expected]
      ]);
      expect(requests).toHaveLength(2);
      expect(requests[0]).toBe(requests[1]);
      expect(JSON.stringify(checks)).not.toContain('one-time-code');
    }
  );
});
