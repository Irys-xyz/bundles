import {
  Account,
  RpcProvider,
  WeierstrassSignatureType,
  ec,
  encode,
  Signer as StarknetSignerAlias,
  TypedData,
  typedData
} from "starknet";
import type { Signer } from "../index";
import { SignatureConfig, SIG_CONFIG } from "../../constants";

export default class StarknetSigner implements Signer {
  protected signer: Account;
  public publicKey: Buffer;
  public static address: string;
  private static privateKey: string;
  public static provider: RpcProvider;
  public chainId: string;
  readonly ownerLength: number = SIG_CONFIG[SignatureConfig.STARKNET].pubLength;
  readonly signatureLength: number = SIG_CONFIG[SignatureConfig.STARKNET].sigLength;
  readonly signatureType: number = SignatureConfig.STARKNET;

  // Constructor to set static properties
  constructor(provider: RpcProvider, address: string, pKey: string) {
    StarknetSigner.provider = provider;
    StarknetSigner.address = address;
    StarknetSigner.privateKey = pKey;
    this.signer = new Account(provider, address, pKey);
  }

  public async init() {
    try {
      const signer = new StarknetSignerAlias(StarknetSigner.privateKey);
      const pub_key = await signer.getPubKey();
      let hexKey = pub_key.startsWith("0x") ? pub_key.slice(2) : pub_key;
      this.publicKey = Buffer.from(0 + hexKey, "hex");
      this.chainId = await StarknetSigner.provider.getChainId();
    } catch (error) {
      console.error("Error setting public key or chain ID:", error);
    }
  }

  async sign(message: Uint8Array, _opts?: any): Promise<Uint8Array> {
    if (!this.publicKey) {
      this.init();
    }
    if (!this.signer.signMessage) throw new Error("Selected signer does not support message signing");

    // decode uint8array to retrieve typedData
    const decodedJson = (Buffer.from(message)).toString();
    const decodedTypeData: TypedData = JSON.parse(decodedJson);

    // generate message hash and signature
    const msgHash = typedData.getMessageHash(decodedTypeData, StarknetSigner.address);
    const signature: WeierstrassSignatureType = ec.starkCurve.sign(msgHash, StarknetSigner.privateKey);

    const r = BigInt(signature.r).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const s = BigInt(signature.s).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    // @ts-ignore
    const recovery = signature.recovery.toString(16).padStart(2, "0"); // Convert recovery to hex string

    const rArray = Uint8Array.from(Buffer.from(r, "hex"));
    const sArray = Uint8Array.from(Buffer.from(s, "hex"));
    const recoveryArray = Uint8Array.from(Buffer.from(recovery, "hex"));
    
    // Concatenate the arrays including the chainIdArray
    const result = new Uint8Array(rArray.length + sArray.length + recoveryArray.length);
    result.set(rArray);
    result.set(sArray, rArray.length);
    result.set(recoveryArray, rArray.length + sArray.length);
    return result;
  }

  static async verify(_pk: Buffer, message: Uint8Array, _signature: Uint8Array, _opts?: any): Promise<boolean> {
    // decode uint8array to retrieve typedData
    const decodedJson = (Buffer.from(message)).toString();
    const decodedTypeData: TypedData = JSON.parse(decodedJson);

    // generate message hash and signature
    const msgHash = typedData.getMessageHash(decodedTypeData, StarknetSigner.address);
    const fullPubKey = encode.addHexPrefix(encode.buf2hex(ec.starkCurve.getPublicKey(StarknetSigner.privateKey, true)));

    // verify
    return ec.starkCurve.verify(_signature.slice(0, -1), msgHash, fullPubKey);
  }
}
