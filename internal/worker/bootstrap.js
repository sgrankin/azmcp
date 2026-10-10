(() => {
  const op = globalThis.__azmcpConsole;
  delete globalThis.__azmcpConsole;
  const hostCall = globalThis.__azmcpHostCall;
  delete globalThis.__azmcpHostCall;
  const apply = Reflect.apply;
  const arrayIsArray = Array.isArray;
  const arrayPush = Array.prototype.push;
  const charCodeAt = String.prototype.charCodeAt;
  const hasOwnProperty = Object.prototype.hasOwnProperty;
  const jsonParse = JSON.parse;
  const stringify = JSON.stringify;
  const replace = String.prototype.replace;
  const separators = /[\u2028\u2029]/g;
  const jsonStringify = (value) => {
    const encoded = stringify(value);
    return typeof encoded === "string"
      ? apply(replace, encoded, [separators, (value) => value === "\u2028" ? "\\u2028" : "\\u2029"])
      : encoded;
  };
  const objectKeys = Object.keys;
  const iteratorSymbol = Symbol.iterator;
  const ARTIFACT_STREAM_CHUNK_BYTES = 384 * 1024;
  const ARTIFACT_STREAM_CHUNKS = 192;
  const ARTIFACT_ARRAY_METHOD = "az.artifacts.writeJsonArray";
  const ARTIFACT_LINES_METHOD = "az.artifacts.writeJsonLines";
  const utf8Length = (text) => {
    let bytes = 0;
    for (let index = 0; index < text.length; index += 1) {
      const code = apply(charCodeAt, text, [index]);
      if (code < 0x80) {
        bytes += 1;
      } else if (code < 0x800) {
        bytes += 2;
      } else if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
        const next = apply(charCodeAt, text, [index + 1]);
        if (next >= 0xdc00 && next <= 0xdfff) {
          bytes += 4;
          index += 1;
        } else {
          bytes += 3;
        }
      } else {
        bytes += 3;
      }
    }
    return bytes;
  };
  const hasOwn = (value, key) => apply(hasOwnProperty, value, [key]);
  const writeJsonStream = (helperName, method, arguments) => {
    if (arguments === null || typeof arguments !== "object" || arrayIsArray(arguments)) {
      throw new TypeError(`${helperName} expects {name, values, compression?}`);
    }
    const keys = objectKeys(arguments);
    if ((keys.length !== 2 && keys.length !== 3)
      || !hasOwn(arguments, "name")
      || !hasOwn(arguments, "values")
      || (keys.length === 3 && !hasOwn(arguments, "compression"))) {
      throw new TypeError(`${helperName} expects only name, values, and optional compression`);
    }
    const name = arguments.name;
    const values = arguments.values;
    const compression = hasOwn(arguments, "compression") ? arguments.compression : "identity";
    if (typeof name !== "string" || name.length === 0) {
      throw new TypeError(`${helperName} name must be a non-empty string`);
    }
    if (compression !== "identity" && compression !== "lz4") {
      throw new TypeError(`${helperName} compression must be identity or lz4`);
    }
    const iterable = values !== null
      && (typeof values === "object" || typeof values === "function")
      && typeof values[iteratorSymbol] === "function";
    if (!iterable) {
      throw new TypeError(`${helperName} values must be a synchronous iterable`);
    }

    let streamId = null;
    try {
      const opened = hostCall(method, {phase: "begin", name, compression});
      const openedKeys = opened !== null && typeof opened === "object" && !arrayIsArray(opened)
        ? objectKeys(opened)
        : [];
      if (openedKeys.length !== 1
        || openedKeys[0] !== "streamId"
        || typeof opened.streamId !== "string"
        || opened.streamId.length === 0) {
        throw new Error("artifact stream begin returned an invalid stream ID");
      }
      streamId = opened.streamId;

      let chunk = [];
      let chunkBytes = 2;
      let sequence = 0;
      let items = 0;
      const append = () => {
        if (chunk.length === 0) return;
        if (sequence >= ARTIFACT_STREAM_CHUNKS) {
          throw new RangeError("artifact stream exceeds the chunk limit");
        }
        const appended = hostCall(method, {
          phase: "append",
          streamId,
          sequence,
          values: chunk,
        });
        const appendedKeys = appended !== null
          && typeof appended === "object"
          && !arrayIsArray(appended)
          ? objectKeys(appended)
          : [];
        if (appendedKeys.length !== 1
          || appendedKeys[0] !== "acceptedSequence"
          || appended.acceptedSequence !== sequence) {
          throw new Error("artifact stream append returned an invalid acknowledgement");
        }
        sequence += 1;
        chunk = [];
        chunkBytes = 2;
      };

      for (const value of values) {
        const encoded = jsonStringify(value);
        if (encoded === undefined) {
          throw new TypeError("artifact stream items must be JSON serializable");
        }
        const encodedBytes = utf8Length(encoded);
        if (encodedBytes + 2 > ARTIFACT_STREAM_CHUNK_BYTES) {
          throw new RangeError("one artifact stream item exceeds the chunk limit");
        }
        const separatorBytes = chunk.length === 0 ? 0 : 1;
        if (chunkBytes + separatorBytes + encodedBytes > ARTIFACT_STREAM_CHUNK_BYTES) {
          append();
        }
        apply(arrayPush, chunk, [jsonParse(encoded)]);
        chunkBytes += (chunk.length === 1 ? 0 : 1) + encodedBytes;
        items += 1;
      }
      append();
      const receipt = hostCall(method, {
        phase: "finish",
        streamId,
        chunks: sequence,
        items,
      });
      streamId = null;
      return receipt;
    } catch (error) {
      if (streamId !== null) {
        try {
          hostCall(method, {phase: "abort", streamId});
        } catch (_) {}
      }
      throw error;
    }
  };
  const writeJsonArray = (arguments) =>
    writeJsonStream("writeJsonArray", ARTIFACT_ARRAY_METHOD, arguments);
  const writeJsonLines = (arguments) =>
    writeJsonStream("writeJsonLines", ARTIFACT_LINES_METHOD, arguments);
  const text = (args) => args.map((value) => {
    try {
      if (typeof value === "string") return value;
      const encoded = JSON.stringify(value);
      return encoded === undefined ? String(value) : encoded;
    } catch (_) {
      try { return String(value); } catch (_) { return "[unprintable]"; }
    }
  }).join(" ");
  const write = (...args) => op(text(args));
  const PEEK_LIMIT = 32;
  const PEEK_VISIT_LIMIT = PEEK_LIMIT * 2;
  const shapeType = (value) => {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  };
  const boundedShape = (value) => {
    try {
      const type = shapeType(value);
      if (type === "string") return { type, length: value.length };
      if (type === "array") {
        const count = Math.min(value.length, PEEK_LIMIT);
        const counts = Object.create(null);
        for (let index = 0; index < count; index += 1) {
          const childType = shapeType(value[index]);
          counts[childType] = (counts[childType] || 0) + 1;
        }
        const result = { type, length: value.length, counts };
        if (value.length > count) {
          result.itemsOmitted = value.length - count;
          result.countsSampled = true;
        }
        return result;
      }
      if (type === "object") {
        const sampledKeys = [];
        let ownKeyBeyondSample = false;
        let visitLimitReached = false;
        let visits = 0;
        for (const key in value) {
          if (visits >= PEEK_VISIT_LIMIT) {
            visitLimitReached = true;
            break;
          }
          visits += 1;
          if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
          if (sampledKeys.length >= PEEK_LIMIT) {
            ownKeyBeyondSample = true;
            break;
          }
          sampledKeys.push(key);
        }
        const keys = sampledKeys.map((key) =>
          key.length > 128 ? key.slice(0, 128) : key);
        keys.sort();
        const counts = Object.create(null);
        for (const key of sampledKeys) {
          let childType = "unavailable";
          try { childType = shapeType(value[key]); } catch (_) {}
          counts[childType] = (counts[childType] || 0) + 1;
        }
        const result = { type, keys, counts };
        if (ownKeyBeyondSample || visitLimitReached) {
          result.keyCountAtLeast = sampledKeys.length + (ownKeyBeyondSample ? 1 : 0);
          result.keysSampled = true;
          result.hasMore = true;
          result.countsSampled = true;
        } else {
          result.keyCount = keys.length;
        }
        return result;
      }
      return { type };
    } catch (_) {
      return { type: "unavailable" };
    }
  };
  Object.defineProperty(globalThis, "console", {
    value: Object.freeze({ log: write, debug: write, info: write, warn: write, error: write }),
    writable: false,
    configurable: false,
    enumerable: true,
  });
  Object.defineProperty(globalThis, "az", {
    value: Object.freeze(Object.assign(Object.create(null), {
      request: (arguments) => hostCall("az.request", arguments),
      graph: (arguments) => hostCall("az.graph", arguments),
      ref: (refId) => hostCall("az.ref", { refId }),
      peek: (value) => boundedShape(value),
      metrics: Object.freeze(Object.assign(Object.create(null), {
        single: (arguments) => hostCall("az.metrics.single", arguments),
        batch: (arguments) => hostCall("az.metrics.batch", arguments),
      })),
      logs: Object.freeze(Object.assign(Object.create(null), {
        query: (arguments) => hostCall("az.logs.query", arguments),
      })),
      artifacts: Object.freeze(Object.assign(Object.create(null), {
        writeJson: (arguments) => hostCall("az.artifacts.writeJson", arguments),
        writeJsonArray,
        writeJsonLines,
      })),
    })),
    writable: false,
    configurable: false,
    enumerable: true,
  });
  try { delete globalThis.Deno; } catch (_) { globalThis.Deno = undefined; }
  try { delete globalThis.__bootstrap; } catch (_) { globalThis.__bootstrap = undefined; }
})();
