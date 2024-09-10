import {
  Account,
  RpcProvider,
  Signature,
  WeierstrassSignatureType,
  ec,
  encode,
  typedData,
  Signer as StarknetSignerAlias,
  TypedData,
  TypedDataRevision,
} from "starknet";
import type { Signer } from "../index";
import { SignatureConfig, SIG_CONFIG } from "../../constants";

// const SN_MAIN = "0x534e5f4d41494e"
const SN_SEPOLIA = "0x534e5f5345504f4c4941";
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

  // async sign(message: Uint8Array, _opts?: any): Promise<Uint8Array> {
  //   if (!this.publicKey) {
  //     this.init();
  //   }
  //   if (!this.signer.signMessage) throw new Error("Selected signer does not support message signing");
  //   let chainId = await this.signer.getChainId();
  //   let message_to_felt = convertToFelt252(message);
  //   let TypedDataMessage = typed_domain({ chainId: chainId, message: message_to_felt });
  //   let signature: Signature = (await this.signer.signMessage(TypedDataMessage.typemessage)) as WeierstrassSignatureType;

  //   const r = BigInt(signature.r).toString(16).padStart(64, "0");
  //   const s = BigInt(signature.s).toString(16).padStart(64, "0");
  //   // @ts-ignore
  //   const recovery = signature.recovery.toString(16).padStart(2, "0");

  //   const rArray = Uint8Array.from(Buffer.from(r, "hex"));
  //   const sArray = Uint8Array.from(Buffer.from(s, "hex"));
  //   const recoveryArray = Uint8Array.from(Buffer.from(recovery, "hex"));

  //   const result = new Uint8Array(rArray.length + sArray.length + recoveryArray.length);
  //   result.set(rArray);
  //   result.set(sArray, rArray.length);
  //   result.set(recoveryArray, rArray.length + sArray.length);

  //   return result;
  // }

  async sign(message: Uint8Array, _opts?: any): Promise<Uint8Array> {
    if (!this.publicKey) {
      this.init();
    }
    if (!this.signer.signMessage) throw new Error("Selected signer does not support message signing");
    let chainId = await this.signer.getChainId();
    let message_to_felt = convertToFelt252(message);

    let typedmessage = await typed_domain({
      chainId,
      message: message_to_felt,
    });

    let signature: Signature = (await this.signer.signMessage(typedmessage.typemessage)) as WeierstrassSignatureType;

    const r = BigInt(signature.r).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    const s = BigInt(signature.s).toString(16).padStart(64, "0"); // Convert BigInt to hex string
    // @ts-ignore
    const recovery = signature.recovery.toString(16).padStart(2, "0"); // Convert recovery to hex string
    const c = BigInt(chainId).toString(16).padStart(8, "0");

    const rArray = Uint8Array.from(Buffer.from(r, "hex"));
    const sArray = Uint8Array.from(Buffer.from(s, "hex"));
    const recoveryArray = Uint8Array.from(Buffer.from(recovery, "hex"));
    // Assuming chainId is in hexadecimal format, and converting it to Uint8Array
    const chainIdArray = Uint8Array.from(Buffer.from(c, "hex"));

    // Concatenate the arrays including the chainIdArray
    const result = new Uint8Array(rArray.length + sArray.length + recoveryArray.length + chainIdArray.length);
    result.set(rArray);
    result.set(sArray, rArray.length);
    result.set(recoveryArray, rArray.length + sArray.length);
    result.set(chainIdArray, rArray.length + sArray.length + recoveryArray.length);
    return result;
  }

  // static async verify(_pk: Buffer, message: Uint8Array, _signature: Uint8Array, _opts?: any): Promise<boolean> {
  //   let chainId = await this.provider.getChainId();
  //   let message_to_felt = convertToFelt252(message);
  //   let TypedDataMessage = typed_domain({ chainId, message: message_to_felt });

  //   const fullPubKey = encode.addHexPrefix(encode.buf2hex(ec.starkCurve.getPublicKey(StarknetSigner.privateKey, true)));

  //   const msgHash = typedData.getMessageHash(TypedDataMessage.typemessage, StarknetSigner.address);

  //   return ec.starkCurve.verify(_signature.slice(0, -1), msgHash, fullPubKey);
  // }

  static async verify(_pk: Buffer, message: Uint8Array, _signature: Uint8Array, _opts?: any): Promise<boolean> {
    const sepolia = BigInt(SN_SEPOLIA).toString(16).padStart(8, "0");
    const sepolia_array = Uint8Array.from(Buffer.from(sepolia, "hex"));
    // Check if the last 10 bytes of the signature match sepoliaArray
    const isSepolia = await _signature.slice(-10).every((v, i) => v === sepolia_array[i]);

    // If it's sepolia, return the last 10 bytes, else return the last 7 bytes
    const uint8ChainId = isSepolia ? (await _signature).slice(-10) : (await _signature).slice(-7);
    const hexString =
      "0x" +
      Array.from(uint8ChainId)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    let message_to_string = convertToFelt252(message);
    let typemessage = await typed_domain({
      chainId: hexString,
      message: message_to_string,
    });
    const msgHash = typedData.getMessageHash(typemessage.typemessage, StarknetSigner.address);
    const fullPubKey = encode.addHexPrefix(encode.buf2hex(ec.starkCurve.getPublicKey(StarknetSigner.privateKey, true)));
    return ec.starkCurve.verify(_signature.slice(0, 64), msgHash, fullPubKey);
  }
}

// Utility function to convert Uint8Array to felt252
function convertToFelt252(data: Uint8Array): bigint[] {
  const felt252Array: bigint[] = [];
  const felt252Size = 31;

  for (let i = 0; i < data.length; i += felt252Size) {
    let value = BigInt(0);
    for (let j = 0; j < felt252Size && i + j < data.length; j++) {
      value = (value << BigInt(8)) | BigInt(data[i + j]);
    }
    felt252Array.push(value);
  }

  return felt252Array;
}

interface TypedParam {
  chainId: string | number;
  message: bigint[];
}

export const typed_domain = ({ chainId, message }: TypedParam): { typemessage: TypedData } => {
  const typemessage: TypedData = {
    domain: {
      name: "Arbundle",
      chainId: chainId,
      version: "1.0.2",
      revision: TypedDataRevision.ACTIVE,
    },
    message: {
      message,
    },
    primaryType: "Message",
    types: {
      Message: [{ name: "message", type: "felt*" }],
      StarknetDomain: [
        { name: "name", type: "string" },
        { name: "chainId", type: "felt" },
        { name: "version", type: "string" },
      ],
    },
  };
  return {
    typemessage,
  };
};
