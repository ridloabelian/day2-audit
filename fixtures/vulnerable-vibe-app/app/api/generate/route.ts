import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

declare const prisma: {
  $queryRawUnsafe: (sql: string) => Promise<unknown>;
  generation: { create: (args: { data: { prompt: string } }) => Promise<unknown> };
};

async function saveAuditLog() {
  return true;
}

export async function POST(req: Request) {
  const body = (await req.json()) as { prompt: string };

  const enriched = await fetch('http://localhost:8000/internal/enrich', {
    method: 'POST',
    body: JSON.stringify({ prompt: body.prompt }),
  });
  await enriched.json();

  const existing = await prisma.$queryRawUnsafe(
    `SELECT * FROM generations WHERE prompt = '${body.prompt}'`,
  );

  let result = null;
  while (true) {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: body.prompt }],
    });
    result = completion.choices[0]?.message?.content;
    if (result) break;
  }

  try {
    await saveAuditLog();
  } catch (err) {}

  await prisma.generation.create({ data: { prompt: body.prompt } });

  return Response.json(
    { result, existing },
    {
      headers: {
        'Access-Control-Allow-Origin': '*',
      },
    },
  );
}
