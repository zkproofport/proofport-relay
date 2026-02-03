import Redis from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://172.28.0.21:6379';

let redis: Redis | null = null;
let available = false;

export function getRedis(): Redis | null {
  return available ? redis : null;
}

export async function initRedis(): Promise<void> {
  return new Promise((resolve) => {
    redis = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 5) return null;
        return Math.min(times * 500, 3000);
      },
      lazyConnect: true,
    });

    redis.on('connect', () => {
      console.log('[Redis] Connected');
      available = true;
    });

    redis.on('error', (err) => {
      console.warn('[Redis] Connection error (falling back to in-memory):', err.message);
      available = false;
    });

    redis.on('close', () => {
      available = false;
    });

    redis
      .connect()
      .then(() => {
        available = true;
        resolve();
      })
      .catch(() => {
        console.warn('[Redis] Could not connect, using in-memory fallback');
        available = false;
        resolve();
      });
  });
}

// In-memory fallback store (for development without Redis)
const memoryStore = new Map<string, { value: string; expiresAt: number }>();

function cleanExpired() {
  const now = Date.now();
  for (const [key, entry] of memoryStore) {
    if (entry.expiresAt > 0 && entry.expiresAt <= now) {
      memoryStore.delete(key);
    }
  }
}

export async function cacheSet(key: string, value: string, ttlSeconds: number): Promise<void> {
  const r = getRedis();
  if (r) {
    await r.set(key, value, 'EX', ttlSeconds);
  } else {
    memoryStore.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }
}

export async function cacheGet(key: string): Promise<string | null> {
  const r = getRedis();
  if (r) {
    return r.get(key);
  }
  cleanExpired();
  const entry = memoryStore.get(key);
  if (!entry) return null;
  if (entry.expiresAt > 0 && entry.expiresAt <= Date.now()) {
    memoryStore.delete(key);
    return null;
  }
  return entry.value;
}

export async function cacheSetNX(key: string, value: string, ttlSeconds: number): Promise<boolean> {
  const r = getRedis();
  if (r) {
    const result = await r.set(key, value, 'EX', ttlSeconds, 'NX');
    return result === 'OK';
  }
  if (memoryStore.has(key)) {
    const entry = memoryStore.get(key)!;
    if (entry.expiresAt > 0 && entry.expiresAt <= Date.now()) {
      memoryStore.delete(key);
    } else {
      return false;
    }
  }
  memoryStore.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  return true;
}

export async function cacheDel(key: string): Promise<void> {
  const r = getRedis();
  if (r) {
    await r.del(key);
  } else {
    memoryStore.delete(key);
  }
}
