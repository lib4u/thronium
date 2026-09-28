import test from 'node:test';
import assert from 'node:assert/strict';
import { importFileKind, maxImportBytes, maxQrImageBytes } from '../src/profiles/import.ts';

test('a text file is bounded by the import limit and only images by the QR limit', () => {
  const text = importFileKind(new TextEncoder().encode('socks://192.0.2.'), 'text/plain', false);
  assert.deepEqual(text, { image: false, limit: maxImportBytes, error: 'import_too_large' });
  const png = importFileKind(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), '', false);
  assert.deepEqual(png, { image: true, limit: maxQrImageBytes, error: 'qr_image_too_large' });
  assert.equal(importFileKind(new Uint8Array(12), '', true).image, true, 'the QR-only picker treats any file as an image');
});
