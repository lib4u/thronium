import { decodeQrImage } from '../shared/qrImage.ts';
import { importFileKind } from './import';

export async function readImportFile(
  file: File,
  qrOnly = false,
): Promise<{ text: string; filename: string }> {
  const head = new Uint8Array(await file.slice(0, 12).arrayBuffer());
  const { image, limit, error } = importFileKind(head, file.type, qrOnly);
  if (file.size > limit) throw new Error(error);
  if (image) return { text: (await decodeQrImage(file)).join('\n'), filename: file.name };
  const bytes = new Uint8Array(await file.arrayBuffer());
  const encoding =
    bytes[0] === 0xff && bytes[1] === 0xfe
      ? 'utf-16le'
      : bytes[0] === 0xfe && bytes[1] === 0xff
        ? 'utf-16be'
        : 'utf-8';
  let text: string;
  try {
    text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
  } catch {
    throw new Error('fileError');
  }
  // eslint-disable-next-line no-control-regex -- Binary control characters make a text configuration invalid.
  if (/[\u0000-\u0008\u000E-\u001F]/.test(text)) throw new Error('fileError');
  return { text, filename: file.name };
}
