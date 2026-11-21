import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 15_000,
});

declare function getServerSession(): Promise<{ user?: { id: string } } | null>;
declare const ratelimit: { limit(key: string): Promise<{ success: boolean }> };
declare const prisma: {
  $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown>;
  generation: { create: (args: { data: { userId: string; prompt: string } }) => Promise<unknown> };
};

const MAX_STEPS = 3;

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session?.user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { success } = await ratelimit.limit(session.user.id);
  if (!success) {
    return Response.json({ error: 'Too Many Requests' }, { status: 429 });
  }

  const body = (await req.json()) as { prompt: string };
  const internalUrl = process.env.INTERNAL_API_URL;
  if (!internalUrl) {
    return Response.json({ error: 'Missing INTERNAL_API_URL' }, { status: 500 });
  }

  const enriched = await fetch(`${internalUrl}/enrich`, {
    method: 'POST',
    body: JSON.stringify({ prompt: body.prompt }),
    signal: AbortSignal.timeout(5_000),
  });
  await enriched.json();

  const existing = await prisma.$queryRaw`SELECT * FROM generations WHERE prompt = ${body.prompt}`;

  let result: string | null = null;
  for (let step = 0; step < MAX_STEPS; step++) {
    const completion = await openai.chat.completions.create(
      {
        model: 'gpt-4o',
        max_tokens: 1024,
        messages: [{ role: 'user', content: body.prompt }],
      },
      { timeout: 15_000 },
    );
    result = completion.choices[0]?.message?.content ?? null;
    if (result) break;
  }

  try {
    await prisma.generation.create({
      data: { userId: session.user.id, prompt: body.prompt },
    });
  } catch (err) {
    console.error('Failed to persist generation record', err);
    return Response.json({ error: 'Persistence error' }, { status: 500 });
  }

  const allowedOrigin = process.env.ALLOWED_ORIGIN ?? 'https://app.example.com';
  return Response.json(
    { result, existing },
    {
      headers: {
        'Access-Control-Allow-Origin': allowedOrigin,
      },
    },
  );
}
