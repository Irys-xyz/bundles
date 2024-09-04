import * as bundlesSrc from "./src";
import * as stream from "./src/stream";
const expObj = { ...bundlesSrc, stream };
globalThis.bundles ??= expObj;
export * from "./src/index";
export * from "./src/stream";
export default expObj;
export const bundles = expObj;
