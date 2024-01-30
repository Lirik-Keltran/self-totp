import { parseArgs } from "util";
import decode from "base32-decode"
import jsSHA from "jssha";

const { values  } = parseArgs({
  args: Bun.argv,
  options: {
    code: {
      type: "string",
      short: "c",
    },
  },
  strict: false,
  allowPositionals: true,
});

if(values.code === undefined) {
  process.exit(1);
}

const uintToBuf = (num: number) => {
  const buf = new ArrayBuffer(8);
  const arr = new Uint8Array(buf);
  let acc = num;

  for (let i = 7; i >= 0; i--) {
    if (acc === 0) break;
    arr[i] = acc & 255;
    acc -= arr[i];
    acc /= 256;
  }

  return buf;
};

const getTOTP = (code: string) => {
  const time = Math.floor(Date.now() / 1000 / 30);
  const count = uintToBuf(time)
  const key = decode(code, "RFC3548");

  const hmac = new jsSHA("SHA-1", "ARRAYBUFFER");
  hmac.setHMACKey(key, "ARRAYBUFFER")
  hmac.update(count);
  const hash = hmac.getHash("UINT8ARRAY");


  const offset = hash[hash.length-1] & 0xf;

  const otp = (((hash[offset] & 0x7F) << 24)
      | ((hash[offset + 1] & 0xFF) << 16)
      | ((hash[offset + 2] & 0xFF) << 8)
      | (hash[offset + 3] & 0xFF)) % 10 ** 6;

  return otp.toString().padStart(6, "0");
}

console.log(getTOTP(values.code as string))
