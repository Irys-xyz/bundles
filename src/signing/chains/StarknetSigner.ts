import type { RpcProvider, WeierstrassSignatureType, TypedData, BigNumberish } from "starknet";
import { Account, ec, encode, hash, typedData } from "starknet";
import type { Signer } from "../index";
import { SignatureConfig, SIG_CONFIG } from "../../constants";

export default class StarknetSigner implements Signer {
  protected signer: Account;
  public publicKey: Buffer;
  public address: string;
  private privateKey: string;
  public provider: RpcProvider;
  public chainId: string;
  readonly ownerLength: number = SIG_CONFIG[SignatureConfig.STARKNET].pubLength;
  readonly signatureLength: number = SIG_CONFIG[SignatureConfig.STARKNET].sigLength;
  readonly signatureType: number = SignatureConfig.STARKNET;

  constructor(provider: RpcProvider, address: string, pKey: string) {
    this.provider = provider;
    this.address = address;
    this.privateKey = pKey;
    this.signer = new Account(provider, address, pKey);
  }

  public async init(): Promise<void> {
    try {
      const pubKey = encode.addHexPrefix(encode.buf2hex(ec.starkCurve.getPublicKey(this.privateKey, true)));
      const hexKey = pubKey.startsWith("0x") ? pubKey.slice(2) : pubKey;

      this.publicKey = Buffer.from(hexKey, "hex");
      this.chainId = await this.provider.getChainId();
    } catch (error) {
      console.error("Error setting public key or chain ID:", error);
    }
  }

  async sign(message: Uint8Array, _opts?: any): Promise<Uint8Array> {
    if (!this.publicKey) {
      await this.init();
    }
    if (!this.signer.signMessage) throw new Error("Selected signer does not support message signing!");

    // generate message hash and signature
    const chainId = this.chainId;
    const msg = hash.computeHashOnElements(uint8ArrayToBigNumberishArray(message));
    const data: TypedData = getTypedData(msg, chainId);
    const signature = (await this.signer.signMessage(data)) as unknown as WeierstrassSignatureType;

    const r = BigInt(signature.r).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const s = BigInt(signature.s).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const address = this.signer.address.replace(/^0x0?|^0x/, "").padStart(64, "0");

    const rArray = Uint8Array.from(Buffer.from(r, "hex"));
    const sArray = Uint8Array.from(Buffer.from(s, "hex"));
    const addressToArray = Uint8Array.from(Buffer.from(address, "hex"));
    const chainIdToArray = Uint8Array.from(Buffer.from(chainId.replace(/^0x/, "").padStart(64, "0"), "hex"));

    // Concatenate the arrays
    const result = new Uint8Array(rArray.length + sArray.length + addressToArray.length + chainIdToArray.length);
    result.set(rArray);
    result.set(sArray, rArray.length);
    result.set(addressToArray, rArray.length + sArray.length);
    result.set(chainIdToArray, rArray.length + sArray.length + addressToArray.length);

    // check signature is of required length
    if (result.length != 128) throw new Error("Signature length must be 128 bytes!");

    return result;
  }

  static async verify(_pk: Buffer, message: Uint8Array, _signature: Uint8Array, _opts?: any): Promise<boolean> {
    const rLength = 32;
    const sLength = 32;
    const addressLength = 32;
    const chainIdLength = 32;

    // retrieve address from signature
    const addressArrayRetrieved = _signature.slice(rLength + sLength, rLength + sLength + addressLength);
    const originalAddress = "0x" + Buffer.from(addressArrayRetrieved).toString("hex");

    // retrieve chainId from signature
    const chainIdArrayRetrieved = _signature.slice(rLength + sLength + addressLength, rLength + sLength + addressLength + chainIdLength);
    const originalChainId = "0x" + Buffer.from(chainIdArrayRetrieved).toString("hex");

    // calculate full public key
    const fullPubKey = encode.addHexPrefix(encode.buf2hex(_pk));

    // generate message hash and signature
    const msg = hash.computeHashOnElements(uint8ArrayToBigNumberishArray(message));
    const data: TypedData = getTypedData(msg, originalChainId);
    const msgHash = typedData.getMessageHash(data, originalAddress);
    const signature = _signature.slice(0, -64);

    // verify
    return ec.starkCurve.verify(signature, msgHash, fullPubKey);
  }
}

// convert message to TypedData format
export function getTypedData(message: string, chainId: string): TypedData {
  const typedData: TypedData = {
    types: {
      StarkNetDomain: [
        { name: "name", type: "shortstring" },
        { name: "version", type: "shortstring" },
        { name: "chainId", type: "shortstring" },
      ],
      SignedMessage: [{ name: "transactionHash", type: "shortstring" }],
    },
    primaryType: "SignedMessage",
    domain: {
      name: "Irys",
      version: "1",
      chainId: chainId,
    },
    message: {
      transactionHash: message,
    },
  };
  return typedData;
}

// convert Uint8Array to BigNumberish
export function uint8ArrayToBigNumberishArray(uint8Arr: Uint8Array): BigNumberish[] {
  const chunkSize = 31; // 252 bits = 31.5 bytes, but using 31 bytes for safety
  const bigNumberishArray: BigNumberish[] = [];

  for (let i = 0; i < uint8Arr.length; i += chunkSize) {
    // Extract a chunk of size 31 bytes
    const chunk = uint8Arr.slice(i, i + chunkSize);

    // Convert the chunk to a bigint
    let bigIntValue = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      bigIntValue = (bigIntValue << BigInt(8)) + BigInt(chunk[j]);
    }

    bigNumberishArray.push(bigIntValue);
  }

  return bigNumberishArray;
}
