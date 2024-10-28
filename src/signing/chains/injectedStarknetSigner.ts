import type { RpcProvider, TypedData, WalletAccount } from "starknet";
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
    this.chainId = await this.provider.getChainId();
  }

  async sign(message: Uint8Array, _opts?: any): Promise<Uint8Array> {
    if (!this.walletAccount.signMessage) throw new Error("Selected signer does not support message signing");

    // generate message hash and signature
    const chainId = this.chainId;
    const msg = hash.computeHashOnElements(uint8ArrayToBigNumberishArray(message));
    const data: TypedData = getTypedData(msg, chainId);
    const signature = await this.walletAccount.signMessage(data);

    // due to account abstraction different wallets, return different signature types.
    // the last two components in the array are mostly the r and s components
    const rsComponents = Array.from(signature).slice(-2);
    const r = BigInt(rsComponents[0]).toString(16).padStart(64, "0");
    const s = BigInt(rsComponents[1]).toString(16).padStart(64, "0");
    const address = this.walletAccount.address.replace(/^0x0?|^0x/, "").padStart(64, "0");

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
    if (result.length !== 128) throw new Error("Signature length must be 128 bytes!");

    return result;
  }

  static async verify(pubkey: Buffer, message: Uint8Array, signature: Uint8Array, _opts?: any): Promise<boolean> {
    const rLength = 32;
    const sLength = 32;
    const addressLength = 32;
    const chainIdLength = 32;

    // retrieve address from signature
    const addressArrayRetrieved = signature.slice(rLength + sLength, rLength + sLength + addressLength);
    const originalAddress = "0x" + Buffer.from(addressArrayRetrieved).toString("hex");

    // retrieve chainId from signature
    const chainIdArrayRetrieved = signature.slice(rLength + sLength + addressLength, rLength + sLength + addressLength + chainIdLength);
    const originalChainId = "0x" + Buffer.from(chainIdArrayRetrieved).toString("hex");

    // calculate full public key
    const fullPubKey = encode.addHexPrefix(encode.buf2hex(pubkey));

    // generate message hash and signature
    const msg = hash.computeHashOnElements(uint8ArrayToBigNumberishArray(message));
    const data: TypedData = getTypedData(msg, originalChainId);
    const msgHash = typedData.getMessageHash(data, originalAddress);
    const trimmedSignature = signature.slice(0, -64);

    // verify
    return ec.starkCurve.verify(trimmedSignature, msgHash, fullPubKey);
  }
}
