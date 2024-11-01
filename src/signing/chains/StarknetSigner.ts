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
    const pubKey = encode.addHexPrefix(encode.buf2hex(ec.starkCurve.getPublicKey(this.privateKey, true)));
    const address = this.signer.address;

    // get pubkey and address buffers
    const pubKeyBuffer = Buffer.from(pubKey.startsWith("0x") ? pubKey.slice(2) : pubKey, "hex");
    const addressBuffer = Buffer.from(address.startsWith("0x") ? address.slice(2) : address, "hex");

    // concatenate buffers as pubKey
    this.publicKey = Buffer.concat([pubKeyBuffer, addressBuffer]);

    this.chainId = await this.provider.getChainId();
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

    const rArray = Uint8Array.from(Buffer.from(r, "hex"));
    const sArray = Uint8Array.from(Buffer.from(s, "hex"));
    const chainIdToArray = Uint8Array.from(Buffer.from(chainId.replace(/^0x/, "").padStart(64, "0"), "hex"));

    // Concatenate the arrays
    const result = new Uint8Array(rArray.length + sArray.length + chainIdToArray.length);
    result.set(rArray);
    result.set(sArray, rArray.length);
    result.set(chainIdToArray, rArray.length + sArray.length);

    // check signature is of required length
    if (result.length !== 96) throw new Error("Signature length must be 96 bytes!");

    return result;
  }

  static async verify(pubkey: Buffer, message: Uint8Array, signature: Uint8Array, _opts?: any): Promise<boolean> {
    const rLength = 32;
    const sLength = 32;

    // retrieve pubKey and address from pubKey
    const originalPubKey = pubkey.slice(0, 33);
    const originalAddress = "0x" + Buffer.from(pubkey.slice(33)).toString("hex");

    // retrieve chainId from signature
    const chainIdArrayRetrieved = signature.slice(rLength + sLength);
    const originalChainId = "0x" + Buffer.from(chainIdArrayRetrieved).toString("hex");

    // calculate full public key
    const fullPubKey = encode.addHexPrefix(encode.buf2hex(originalPubKey));

    // generate message hash and signature
    const msg = hash.computeHashOnElements(uint8ArrayToBigNumberishArray(message));
    const data: TypedData = getTypedData(msg, originalChainId);
    const msgHash = typedData.getMessageHash(data, originalAddress);
    const trimmedSignature = signature.slice(0, -32);

    // verify
    return ec.starkCurve.verify(trimmedSignature, msgHash, fullPubKey);
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
