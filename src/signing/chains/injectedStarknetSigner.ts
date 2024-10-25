import type { RpcProvider, WeierstrassSignatureType, TypedData, WalletAccount } from "starknet";
import { ec, encode, hash, typedData } from "starknet";
import type { Signer } from "../index";
import { getTypedData, uint8ArrayToBigNumberishArray } from "./StarknetSigner";
import { SignatureConfig, SIG_CONFIG } from "../../constants";

export default class InjectedStarknetSigner implements Signer {
  public walletAccount: WalletAccount;
  public publicKey: Buffer;
  public provider: RpcProvider;
  public chainId: string;
  readonly ownerLength: number = SIG_CONFIG[SignatureConfig.STARKNET].pubLength;
  readonly signatureLength: number = SIG_CONFIG[SignatureConfig.STARKNET].sigLength;
  readonly signatureType: number = SignatureConfig.STARKNET;

  constructor(provider: RpcProvider, walletAccount: WalletAccount) {
    this.provider = provider;
    this.walletAccount = walletAccount;
  }

  public async init(): Promise<void> {
    try {
      this.chainId = await this.provider.getChainId();
    } catch (error) {
      console.error("Error setting chain ID:", error);
    }
  }

  async sign(message: Uint8Array, _opts?: any): Promise<Uint8Array> {
    if (!this.walletAccount.signMessage) throw new Error("Selected signer does not support message signing");

    // generate message hash and signature
    const chainId = this.chainId;
    const msg = hash.computeHashOnElements(uint8ArrayToBigNumberishArray(message));
    const data: TypedData = getTypedData(msg, chainId);
    const signature = (await this.walletAccount.signMessage(data)) as unknown as WeierstrassSignatureType;

    const r = BigInt(signature[3]).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const s = BigInt(signature[4]).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const address = this.walletAccount.address.replace(/^0x0?|^0x/, "");

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
    if (result.length != 127) throw new Error("Signature length must be 127 bytes!");

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
