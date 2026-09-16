const crypto = require('crypto');
const { db } = require('./db');
const OPERATION = 'POST:/incidents';
const KEY_TTL_HOURS = 24;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonicalize(value[key]);
      return result;
    }, {});
  }
  return value;
}

function hashRequest(body) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(body))).digest('hex');
}

async function createIncident(req, res) {
  const key = req.get('Idempotency-Key');
  if (!key || !key.trim()) return res.status(400).json({ error: 'idempotency_key_required' });

  const tenantId = req.user.tenantId;
  const requestHash = hashRequest(req.body);

  const result = await db.tx(async t => {
    // The unique constraint serializes claims across all application instances.
    // A conflicting insert waits for the first transaction before this row is read.
    const claimed = await t.oneOrNone(
      `INSERT INTO idempotency_keys
         (tenant_id, operation, key, request_hash, state, expires_at)
      VALUES ($1, $2, $3, $4, 'processing', now() + ($5 * interval '1 hour'))
      ON CONFLICT (tenant_id, operation, key) DO UPDATE
         SET request_hash = EXCLUDED.request_hash,
             state = 'processing',
             status_code = NULL,
             response_headers = NULL,
             response_body = NULL,
             expires_at = EXCLUDED.expires_at,
             updated_at = now()
         WHERE idempotency_keys.expires_at <= now()
       RETURNING *`,
      [tenantId, OPERATION, key, requestHash, KEY_TTL_HOURS]
    );

    const record = claimed || await t.one(
      `SELECT * FROM idempotency_keys
       WHERE tenant_id = $1 AND operation = $2 AND key = $3
       FOR UPDATE`,
      [tenantId, OPERATION, key]
    );

    if (!claimed) {
      if (record.request_hash !== requestHash) {
        return { status: 409, body: { error: 'idempotency_key_conflict' } };
      }
      if (record.state === 'completed') {
        if (!record.status_code || record.response_body === null) {
          throw new Error('completed idempotency record is missing replay metadata');
        }
        return {
          status: record.status_code,
          body: record.response_body,
          headers: record.response_headers,
          replayed: true
        };
      }
      if (record.state === 'processing') {
        return { status: 409, body: { error: 'operation_in_progress' } };
      }
      return { status: 409, body: { error: 'prior_operation_failed' } };
    }

    const incident = await t.one(
      `INSERT INTO incidents (tenant_id, service_id, title, severity)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [tenantId, req.body.serviceId, req.body.title, req.body.severity]
    );
    await t.none(
      `INSERT INTO paging_jobs (tenant_id, incident_id) VALUES ($1, $2)`,
      [tenantId, incident.id]
    );
    // This is deliberately the final write: any earlier failure rolls back the
    // claim, incident, and paging job together instead of leaving stale state.
    await t.one(
      `UPDATE idempotency_keys
       SET state = 'completed', status_code = 201,
           response_headers = $2::jsonb, response_body = $3::jsonb, updated_at = now()
       WHERE id = $1 AND state = 'processing'
       RETURNING id`,
      [record.id, JSON.stringify({}), JSON.stringify(incident)]
    );
    return { status: 201, body: incident };
  });

  if (result.replayed) res.set('Idempotent-Replayed', 'true');
  return res.status(result.status).json(result.body);
}

module.exports = { createIncident, hashRequest };
