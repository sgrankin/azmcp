(() => {
  const send = globalThis.__azmcpSend;
  const complete = globalThis.__azmcpComplete;
  const stringify = JSON.stringify;
  const parse = JSON.parse;
  const apply = Reflect.apply;
  const PromiseType = Promise;
  const promiseResolve = Promise.resolve;
  const promiseThen = Promise.prototype.then;
  const mapGet = Map.prototype.get;
  const mapSet = Map.prototype.set;
  const mapDelete = Map.prototype.delete;
  const ErrorType = Error;
  const StringType = String;
  const pending = new Map();
  delete globalThis.__azmcpSend;
  delete globalThis.__azmcpComplete;

  const errorText = (error) => {
    try { return StringType(error); } catch (_) { return "JavaScript exception"; }
  };
  globalThis.__azmcpHostCall = (method, arguments) => new PromiseType((resolve, reject) => {
    const encoded = stringify(arguments);
    if (encoded === undefined) throw new TypeError("host-call arguments are not JSON serializable");
    const id = send(method, encoded);
    if (id === 0) throw new ErrorType("host bridge protocol error");
    apply(mapSet, pending, [id, {resolve, reject}]);
  });

  // Go retains this function; caller scripts have no route to its resolver table.
  return (command, first, second, third) => {
    if (command === "watch") {
      apply(promiseThen, apply(promiseResolve, PromiseType, [first]), [
        (value) => {
          try {
            const encoded = stringify(value);
            complete(encoded === undefined ? "null" : encoded, "", "result");
          } catch (error) {
            complete("", errorText(error), "serialization");
          }
        },
        (error) => complete("", errorText(error), "execution"),
      ]);
    } else if (command === "settle") {
      const resolver = apply(mapGet, pending, [first]);
      if (resolver === undefined) throw new ErrorType("host-call response ID mismatch");
      apply(mapDelete, pending, [first]);
      if (second) resolver.resolve(parse(third));
      else resolver.reject(new ErrorType(third));
    } else {
      throw new ErrorType("unknown worker control command");
    }
  };
})()
