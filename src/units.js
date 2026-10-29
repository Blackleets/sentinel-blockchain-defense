/**
 * Format a JSON-RPC wei quantity as ETH without floating-point rounding.
 * The default display precision is eight decimal places (truncated, not rounded).
 */
export function formatWei(value, decimals = 8) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new TypeError("Expected a hexadecimal JSON-RPC quantity");
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new RangeError("decimals must be an integer from 0 to 18");
  }

  const wei = BigInt(value);
  const unit = 10n ** 18n;
  const whole = wei / unit;
  if (decimals === 0) return whole.toString();

  const fraction = (wei % unit).toString().padStart(18, "0").slice(0, decimals);
  return whole.toString() + "." + fraction;
}
