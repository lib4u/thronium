import { command } from './api/command.ts';
import { encodeBytes } from './base64.ts';
import { limits } from './api/generated/limits.ts';

/** Texts of the QR codes the host finds in an image file. */
export async function decodeQrImage(file: Blob): Promise<string[]> {
  if (file.size > limits.maxQrImageBytes) throw Error('qr_image_too_large');
  return command('decodeQrImage', { data: encodeBytes(new Uint8Array(await file.arrayBuffer())) });
}
