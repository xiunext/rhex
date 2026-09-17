ALTER TABLE "OAuthAuthorizationCode"
  ALTER COLUMN "codeChallenge" DROP NOT NULL,
  ALTER COLUMN "codeChallengeMethod" DROP NOT NULL;
