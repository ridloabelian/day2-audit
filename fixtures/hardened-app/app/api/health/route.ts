export async function GET() {
  return Response.json({
    ok: true,
    service: 'hardened-app',
    timestamp: Date.now(),
  });
}
