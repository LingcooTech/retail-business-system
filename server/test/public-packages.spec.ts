import { describe, expect, it } from 'vitest';

import { decryptJson, encryptJson } from '@lingcoo-tech/crypto';
import { ApiError, createApiErrorResponse, isApiErrorResponse } from '@lingcoo-tech/http';
import { createSmtpMailer } from '@lingcoo-tech/mailer';
import {
  hashPassword,
  parseBearerToken,
  signAccessToken,
  verifyAccessToken,
} from '@lingcoo-tech/security';

describe('published Lingcoo packages', () => {
  it('supports password and JWT primitives', async () => {
    const passwordHash = await hashPassword('retail-validation-password');
    expect(passwordHash).toMatch(/^scrypt:v1:/);

    const token = await signAccessToken(
      { sub: 'retail-validation-account', role: 'admin' },
      {
        secret: 'retail-validation-secret-with-at-least-32-bytes',
        issuer: 'retail-business-system',
        audience: 'retail-business-system-api',
      },
    );
    const claims = await verifyAccessToken(token, {
      secret: 'retail-validation-secret-with-at-least-32-bytes',
      issuer: 'retail-business-system',
      audience: 'retail-business-system-api',
    });

    expect(claims.sub).toBe('retail-validation-account');
    expect(parseBearerToken(`Bearer ${token}`)).toBe(token);
  });

  it('supports encrypted settings and HTTP error contracts', () => {
    const encrypted = encryptJson({ provider: 'smtp', enabled: true }, 'retail-secret');
    expect(decryptJson(encrypted, 'retail-secret')).toEqual({
      provider: 'smtp',
      enabled: true,
    });

    const response = createApiErrorResponse(
      new ApiError(409, 'RETAIL_VALIDATION_CONFLICT', 'Validation conflict'),
      'retail-request-id',
    );
    expect(isApiErrorResponse(response)).toBe(true);
    expect(response.error.requestId).toBe('retail-request-id');
  });

  it('exposes a provider-neutral SMTP mailer factory', () => {
    const mailer = createSmtpMailer({
      host: 'smtp.example.test',
      port: 587,
      secure: false,
      user: 'retail@example.test',
      password: 'not-sent-in-validation',
      from: 'retail@example.test',
    });

    expect(mailer.send).toBeTypeOf('function');
  });
});
