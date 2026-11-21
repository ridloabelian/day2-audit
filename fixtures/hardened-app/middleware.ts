const ratelimit = {
  async limit(_key: string) {
    return { success: true };
  },
};

export async function middleware(req: Request) {
  const ip = req.headers.get('x-forwarded-for') ?? 'unknown';
  const { success } = await ratelimit.limit(ip);
  if (!success) {
    return Response.json({ error: 'Too Many Requests' }, { status: 429 });
  }
  const res = new Response(null, { status: 200 });
  const allowedOrigin = process.env.ALLOWED_ORIGIN ?? 'https://app.example.com';
  res.headers.set('Access-Control-Allow-Origin', allowedOrigin);
  return res;
}
