export function hasBit(
  bitmask: Buffer | Uint8Array | number[],
  index: number
): boolean {
  const bytePos = Math.floor(index / 8);
  const bitPos = index % 8;
  return bytePos < bitmask.length && (bitmask[bytePos] & (1 << bitPos)) !== 0;
}

export function bitmaskToIndices(
  bitmask: Buffer | Uint8Array | number[]
): number[] {
  const indices: number[] = [];
  for (let byteIdx = 0; byteIdx < bitmask.length; byteIdx++) {
    for (let bit = 0; bit < 8; bit++) {
      if (bitmask[byteIdx] & (1 << bit)) {
        indices.push(byteIdx * 8 + bit);
      }
    }
  }
  return indices;
}
