import crypto from 'node:crypto';

declare const stripe: {
  webhooks: {
    constructEvent: (body: string, sig: string, secret: string) => { type: string };
  };
};

export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature');
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!sig || !secret) {
    return Response.json({ error: 'Missing signature or webhook secret' }, { status: 400 });
  }

  const rawBody = await req.text();
  const event = stripe.webhooks.constructEvent(rawBody, sig, secret);
  crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sig));
  return Response.json({ received: true, type: event.type });
}
