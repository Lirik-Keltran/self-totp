import { parseArgs } from "util";
import decode from "base32-decode"
import jsSHA from "jssha";
import { pipe } from "fp-ts/lib/function";
import * as O from "fp-ts/Option";
import * as E from "fp-ts/Either";
import * as TE from "fp-ts/TaskEither";
import * as T from "fp-ts/Task";
import { dirname, join }  from "path"

const rootPath = pipe(
    import.meta.path,
    dirname,
    (path) => join(path, ".."),
  )

type Config = {
  codes: Array<string>,
};

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

const value = values.code as string;


const saveAndGetConfig = (code: string | undefined): TE.TaskEither<Error, Config> => {
  const path = join(rootPath, "/config/code.json");

  const read = (): TE.TaskEither<Error, Config> => {
    return TE.tryCatch(
      () => pipe(
        Bun.file(path),
        file => file.json<Config>()
      ),
      E.toError
    );
  };

  const save = (code: string): TE.TaskEither<Error, Config> => {
    const deafultConfig = {
      codes: [code]
    }

    return pipe(
      read(),
      TE.map(config => config.codes.at(-1) === code ? config : ({ codes: [...config.codes, code] })),
      TE.flatMap(config =>
        TE.fromTask(
          () => Bun.write(path, JSON.stringify(config)).then(() => config),
        )
      ),
      TE.orElse(() =>
        TE.fromTask(
          () => Bun.write(path, JSON.stringify(deafultConfig)).then(() => deafultConfig),
        )
      )
    )
  }


  return pipe(
    code,
    O.fromNullable,
    O.fold(
      read,
      save
    )
  );
}

const config = await pipe(
  saveAndGetConfig(value),
  TE.fold(
    (e) => {
      console.error(e);
      process.exit(1);
    },
    config => T.of(config),
  )
)();

const code = config.codes[config.codes.length-1];

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
  const timeToUpdate = Math.floor((Date.now() / 1000 % 30))

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

  return {
    TOTP: otp.toString().padStart(6, "0"),
    timeToUpdate
  };
};


console.log(JSON.stringify(getTOTP(code)))

setInterval(() => {
  console.log(JSON.stringify(getTOTP(code)))
}, 1000)

