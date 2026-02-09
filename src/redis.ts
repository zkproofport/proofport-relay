import Redis from 'ioredis';

const REDIS_URL = process.env.REDIS_URL;
if (!REDIS_URL) throw new Error('REDIS_URL environment variable is required');

let redis: Redis;

export async function initRedis(): Promise<void> {
  redis = new Redis(REDIS_URL!, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      if (times > 5) return null;
      return Math.min(times * 500, 3000);
    },
    lazyConnect: true,
  });

  redis.on('error', (err) => {
    console.error('[Redis] Connection error:', err.message);
  });

  await redis.connect();
  console.log('[Redis] Connected');
}

export async function cacheSet(key: string, value: string, ttlSeconds: number): Promise<void> {
  await redis.set(key, value, 'EX', ttlSeconds);
}

export async function cacheGet(key: string): Promise<string | null> {
  return redis.get(key);
}

export async function cacheSetNX(key: string, value: string, ttlSeconds: number): Promise<boolean> {
  const result = await redis.set(key, value, 'EX', ttlSeconds, 'NX');
  return result === 'OK';
}

export async function cacheDel(key: string): Promise<void> {
  await redis.del(key);
}
