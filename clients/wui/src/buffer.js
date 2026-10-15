import { Buffer } from "buffer";

// The Ledger transports and the APDU layer use the Node Buffer API as a global.
globalThis.Buffer = Buffer;
