export function formatTimestamp(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const parts = Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', second: 'numeric',
  }).formatToParts(date);
  // Date retains milliseconds only; preserve the original fractional digits.
  const fraction = value.match(/\.(\d+)(?:Z|[+-]\d{2}:?\d{2})?$/i)?.[1];
  if (!fraction) return parts.map((part) => part.value).join('');
  const numbers = Intl.NumberFormat(undefined, { useGrouping: false });
  const decimal = numbers.formatToParts(1.1).find((part) => part.type === 'decimal')?.value ?? '.';
  const digits = fraction.replace(/\d/g, (digit) => numbers.format(Number(digit)));
  return parts.map((part) => part.type === 'second' ? `${part.value}${decimal}${digits}` : part.value).join('');
}
