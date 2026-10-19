import Fastify from 'fastify';
import { Type } from '@sinclair/typebox';
import {
  ErrorResponseSchema,
  HealthResponseSchema,
  VersionResponseSchema,
} from './schemas/common.js';
import { closeDb, getDb } from './db/index.js';

const PORT = Number(process.env.API_PORT ?? 3001);
const HOST = process.env.API_HOST ?? '0.0.0.0';

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
  },
});

app.get(
  '/health',
  {
    schema: {
      response: { 200: HealthResponseSchema },
    },
  },
  async () => ({ status: 'ok', service: 'gmd-api' }),
);

app.get(
  '/health/ready',
  {
    schema: {
      response: {
        200: Type.Object(
          { status: Type.String(), database: Type.String() },
          { additionalProperties: false },
        ),
        default: ErrorResponseSchema,
      },
    },
  },
  async (_req, reply) => {
    try {
      const result = await getDb()
        .selectFrom('health_probe')
        .select((eb) => eb.fn.countAll<number>().as('c'))
        .executeTakeFirstOrThrow();
      return { status: 'ok', database: `postgres ok (${result.c} satir)` };
    } catch (err) {
      app.log.error({ err }, 'database kontrolu basarisiz');
      return reply.code(503).send({
        error: 'service_unavailable',
        message: 'veritabani erisilemiyor',
      });
    }
  },
);

app.get(
  '/api/version',
  {
    schema: {
      response: {
        200: VersionResponseSchema,
        default: ErrorResponseSchema,
      },
    },
  },
  async () => ({
    name: 'GMD Market',
    legalName: 'Global Menkul Değerler',
    version: '0.1.0',
  }),
);

async function main(): Promise<void> {
  try {
    await app.listen({ port: PORT, host: HOST });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    void app.close().then(closeDb).then(() => process.exit(0));
  });
}

void main();
