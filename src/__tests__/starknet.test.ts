jest.setTimeout(20000);
import StarknetSigner from "../signing/chains/StarknetSigner";
import { createData } from "../../index";
import Crypto from "crypto";
import { RpcProvider } from "starknet";

const tagsTestVariations = [
  { description: "no tags", tags: undefined },
  { description: "empty tags", tags: [] },
  { description: "single tag", tags: [{ name: "Content-Type", value: "image/png" }] },
  {
    description: "multiple tags",
    tags: [
      { name: "Content-Type", value: "image/png" },
      { name: "hello", value: "world" },
      { name: "lorem", value: "ipsum" },
    ],
  },
];

const dataTestVariations = [
  { description: "empty string", data: "" },
  { description: "small string", data: "hello world" },
  { description: "large string", data: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};':\",./<>?`~" },
  { description: "empty buffer", data: Buffer.from([]) },
  { description: "small buffer", data: Buffer.from("hello world") },
  { description: "large buffer", data: Buffer.from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};':\",./<>?`~") },
];

describe("Typed Starknet Signer", () => {
  let signer: StarknetSigner;
  const provider = new RpcProvider({ nodeUrl: "https://starknet-sepolia.public.blastapi.io" });

  const PrivateKey = "0x0570d0ab0e4bd9735277e8db6c8e19918c64ed50423aa5860235635d2487c7bb";
  const myAddressInStarknet = "0x078e47BBEB4Dc687741825d7bEAD044e229960D3362C0C21F45Bb920db08B0c4";

  beforeAll(async () => {
    signer = new StarknetSigner(provider, myAddressInStarknet, PrivateKey);
    await signer.init();
  });

  it("should sign a known values", async () => {
    const expectedSignature = Buffer.from([
      1, 97, 23, 22, 40, 161, 114, 58, 182, 161, 83, 120, 241, 253, 19, 214, 124, 52, 42, 128, 84, 80, 90, 234, 145, 165, 248, 60, 100, 128, 144, 199,
      2, 156, 193, 110, 55, 251, 188, 35, 208, 120, 137, 147, 61, 2, 89, 55, 112, 71, 203, 130, 242, 167, 100, 226, 76, 181, 116, 210, 80, 226, 17,
      175, 7, 142, 71, 187, 235, 77, 198, 135, 116, 24, 37, 215, 190, 173, 4, 78, 34, 153, 96, 211, 54, 44, 12, 33, 244, 91, 185, 32, 219, 8, 176,
      196, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 78, 95, 83, 69, 80, 79, 76, 73, 65,
    ]);

    const data = Buffer.from("Hello Bundlr!");
    const signature = await signer.sign(data);
    const signatureBuffer = Buffer.from(signature);
    expect(signatureBuffer).toEqual(expectedSignature);
  });

  it("should fail for an invalid signature", async () => {
    const expectedSignature = Buffer.from([
      3, 14, 26, 44, 182, 142, 237, 13, 51, 15, 51, 142, 100, 132, 8, 70, 90, 34, 222, 66, 92, 68, 20, 86, 18, 205, 207, 16, 215, 160, 82, 238, 7,
      227, 27, 134, 157, 27, 47, 233, 175, 89, 26, 104, 127, 142, 192, 227, 45, 149, 179, 169, 202, 38, 75, 242, 68, 84, 75, 8, 222, 153, 188, 225, 7,
      142, 71, 187, 235, 77, 198, 135, 116, 24, 37, 215, 190, 173, 4, 78, 34, 153, 96, 211, 54, 44, 12, 33, 244, 91, 185, 32, 219, 8, 176, 196, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 78, 95, 77, 65, 73, 78,
    ]);

    const data = Buffer.from("Hello World!");
    const signature = await signer.sign(data);
    const signatureBuffer = Buffer.from(signature);
    expect(signatureBuffer).not.toEqual(expectedSignature);
  });

  it("should sign & verify a known values", async () => {
    const data = Buffer.from("Hello Bundlr!");
    const signature = await signer.sign(data);

    const publicKey = signer.publicKey.toString("hex");
    const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
    const isValid = await StarknetSigner.verify(Buffer.from(hexString, "hex"), data, signature);
    expect(isValid).toEqual(true);
  });

  it("should evaulate to false for invalid signature", async () => {
    // generate invalid signature
    const signature = Uint8Array.from([
      3, 14, 26, 44, 182, 142, 237, 13, 51, 15, 51, 142, 100, 132, 8, 70, 90, 34, 222, 66, 92, 68, 20, 86, 18, 205, 207, 16, 215, 160, 82, 238, 7,
      227, 27, 134, 157, 27, 47, 233, 175, 89, 26, 104, 127, 142, 192, 227, 45, 149, 179, 169, 202, 38, 75, 242, 68, 84, 75, 8, 222, 153, 188, 225, 7,
      142, 71, 187, 235, 77, 198, 135, 116, 24, 37, 215, 190, 173, 4, 78, 34, 153, 96, 211, 54, 44, 12, 33, 244, 91, 185, 32, 219, 8, 176, 196, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 78, 95, 77, 65, 73, 78,
    ]);

    // try verifying
    const publicKey = signer.publicKey.toString("hex");
    const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
    const data = Buffer.from("Hello World!");
    const isValid = await StarknetSigner.verify(Buffer.from(hexString, "hex"), data, signature);
    expect(isValid).toEqual(false);
  });

  it("should evaulate to false for invalid message", async () => {
    const data = Buffer.from("Hello Bundlr!");
    const signature = await signer.sign(data);

    const publicKey = signer.publicKey.toString("hex");
    const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
    const invalidData = Buffer.from("Hello World!");
    const isValid = await StarknetSigner.verify(Buffer.from(hexString, "hex"), invalidData, signature);
    expect(isValid).toEqual(false);
  });

  describe("Create & Validate DataItems", () => {
    it("should create a valid dataItem", async () => {
      const data = Buffer.from("Hello, Bundlr!");
      const tags = [{ name: "Hello", value: "Bundlr" }];
      const item = createData(data, signer, { tags });
      await item.sign(signer);
      expect(await item.isValid()).toBe(true);
    });

    describe("With an unknown wallet", () => {
      it("should sign & verify an unknown value", async () => {
        const randSigner = new StarknetSigner(provider, myAddressInStarknet, PrivateKey);
        const randData = Buffer.from(Crypto.randomBytes(256));
        const signature = await randSigner.sign(Uint8Array.from(randData));

        const publicKey = signer.publicKey.toString("hex");
        const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
        const isValid = await StarknetSigner.verify(Buffer.from(hexString, "hex"), randData, signature);
        expect(isValid).toEqual(true);
      });
    });

    describe("and given we want to create a dataItem", () => {
      describe.each(tagsTestVariations)("with $description tags", ({ tags }) => {
        describe.each(dataTestVariations)("and with $description data", ({ data }) => {
          it("should create a valid dataItems", async () => {
            const item = createData(Buffer.from(data), signer, { tags });
            await item.sign(signer);
            expect(await item.isValid()).toBe(true);
          });

          it("should set the correct tags", async () => {
            const item = createData(Buffer.from(data), signer, { tags });
            await item.sign(signer);
            expect(item.tags).toEqual(tags ?? []);
          });

          it("should set the correct data", async () => {
            const item = createData(Buffer.from(data), signer, { tags });
            await item.sign(signer);
            expect(item.rawData).toEqual(Buffer.from(Buffer.from(data)));
          });
        });
      });
    });
  });
});
