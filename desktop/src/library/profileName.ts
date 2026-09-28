// Keep complete flag, skin-tone, keycap and joined emoji sequences together.
const leadingEmoji =
  /^(?:\p{Regional_Indicator}{2}|[#*0-9]\uFE0F?\u20E3|\p{Extended_Pictographic}[\uFE0E\uFE0F]?\p{Emoji_Modifier}?(?:\u200D\p{Extended_Pictographic}[\uFE0E\uFE0F]?\p{Emoji_Modifier}?)*(?:[\u{E0020}-\u{E007E}]+\u{E007F})?)/u;

export function profileName(name: string): { emoji: string; text: string } {
  const trimmed = name.trimStart();
  const emoji = trimmed.match(leadingEmoji)?.[0] || '';
  return { emoji, text: emoji ? trimmed.slice(emoji.length).trimStart() : name };
}
