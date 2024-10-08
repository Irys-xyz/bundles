import type { RpcProvider, WeierstrassSignatureType, BigNumberish } from "starknet";
import { Account, ec, encode, hash } from "starknet";
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
      const pub_key = encode.addHexPrefix(encode.buf2hex(ec.starkCurve.getPublicKey(this.privateKey, true)));
      const hexKey = pub_key.startsWith("0x") ? pub_key.slice(2) : pub_key;

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
    if (!this.signer.signMessage) throw new Error("Selected signer does not support message signing");

    // generate message hash and signature
    const msg: BigNumberish[] = uint8ArrayToBigNumberishArray(message);
    const msgHash = hash.computeHashOnElements(msg);
    const signature: WeierstrassSignatureType = ec.starkCurve.sign(msgHash, this.privateKey);

    const r = BigInt(signature.r).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const s = BigInt(signature.s).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    if (!signature.recovery) throw new Error("signature is missing required recovery component");
    const recovery = signature.recovery.toString(16).padStart(2, "0"); // Convert recovery to hex string

    const rArray = Uint8Array.from(Buffer.from(r, "hex"));
    const sArray = Uint8Array.from(Buffer.from(s, "hex"));
    const recoveryArray = Uint8Array.from(Buffer.from(recovery, "hex"));

    // Concatenate the arrays
    const result = new Uint8Array(rArray.length + sArray.length + recoveryArray.length);
    result.set(rArray);
    result.set(sArray, rArray.length);
    result.set(recoveryArray, rArray.length + sArray.length);
    return result;
  }

  static async verify(_pk: Buffer, message: Uint8Array, _signature: Uint8Array, _opts?: any): Promise<boolean> {
    // generate message hash and signature
    const msg: BigNumberish[] = uint8ArrayToBigNumberishArray(message);
    const msgHash = hash.computeHashOnElements(msg);
    const fullPubKey = encode.addHexPrefix(encode.buf2hex(_pk));

    // verify
    return ec.starkCurve.verify(_signature.slice(0, -1), msgHash, fullPubKey);
  }
}

// helper function to convert Uint8Array -> BigNumberishArray
function uint8ArrayToBigNumberishArray(uint8Arr: Uint8Array): BigNumberish[] {
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
