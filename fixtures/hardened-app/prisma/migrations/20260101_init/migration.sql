-- Initial schema migration
CREATE TABLE "Generation" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "userId" TEXT NOT NULL,
  "prompt" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE "Generation" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own_generations"
  ON "Generation"
  FOR ALL
  USING (auth.uid()::text = "userId");
