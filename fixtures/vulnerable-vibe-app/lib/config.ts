export const clientConfig = {
  supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL ?? '',
  supabaseAdminKey: process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY ?? '',
  stripeSecret: import.meta.env?.VITE_STRIPE_SECRET_KEY ?? '',
};
