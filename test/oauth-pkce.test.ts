import assert from "node:assert/strict"
import test from "node:test"

import {
  createPkceS256Challenge,
  isOAuthPkceRequired,
  isValidPkceCodeVerifier,
  parseOAuthPkceParameters,
  verifyPkceChallenge,
} from "@/lib/oauth-utils"

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

test("OAuth PKCE S256 validates the RFC 7636 example", () => {
  assert.equal(isValidPkceCodeVerifier(verifier), true)
  assert.equal(createPkceS256Challenge(verifier), challenge)
  assert.equal(verifyPkceChallenge({ verifier, challenge, method: "S256" }), true)
  assert.equal(verifyPkceChallenge({ verifier, challenge, method: "plain" }), false)
  assert.equal(verifyPkceChallenge({ verifier: `${verifier}x`, challenge, method: "S256" }), false)
})

test("OAuth PKCE parameter parsing accepts omission and validates S256-only requests", () => {
  assert.equal(isOAuthPkceRequired(null), true)
  assert.equal(isOAuthPkceRequired("client-secret-hash"), false)

  assert.deepEqual(parseOAuthPkceParameters({ codeChallenge: undefined, codeChallengeMethod: undefined }), {
    isPresent: false,
    isValid: true,
    codeChallenge: null,
    codeChallengeMethod: null,
  })
  assert.deepEqual(parseOAuthPkceParameters({ codeChallenge: challenge, codeChallengeMethod: "S256" }), {
    isPresent: true,
    isValid: true,
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
  })

  assert.equal(parseOAuthPkceParameters({ codeChallenge: challenge, codeChallengeMethod: "plain" }).isValid, false)
  assert.equal(parseOAuthPkceParameters({ codeChallenge: challenge }).isValid, false)
  assert.equal(parseOAuthPkceParameters({ codeChallenge: challenge.slice(1), codeChallengeMethod: "S256" }).isValid, false)
  assert.equal(parseOAuthPkceParameters({ codeChallenge: "", codeChallengeMethod: undefined }).isValid, false)
})
