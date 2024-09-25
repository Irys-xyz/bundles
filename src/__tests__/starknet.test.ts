jest.setTimeout(20000);
import StarknetSigner from "../signing/chains/StarknetSigner";
import { RpcProvider, shortString, TypedData } from "starknet";
import { createData } from "../../index";

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

const sampleData: TypedData = {
  types: {
    StarkNetDomain: [
      { name: "name", type: "felt" },
      { name: "version", type: "felt" },
      { name: "chainId", type: "felt" },
      { name: "verifyingContract", type: "felt" }
    ],
    Person: [
      { name: "name", type: "felt" },
      { name: "wallet", type: "felt" }
    ]
  },
  domain: {
    name: "Starknet App",
    version: "1",
    chainId: shortString.encodeShortString('SN_SEPOLIA'),
    verifyingContract: "0x123456789abcdef"
  },
  primaryType: "Person",
  message: {
    name: "Alice",
    wallet: "0xabcdef"
  }
};

const sampleDataTwo: TypedData = {
  types: {
    StarkNetDomain: [
      { name: "name", type: "felt" },
      { name: "version", type: "felt" },
      { name: "chainId", type: "felt" },
    ],
    Vote: [
      { name: "voter", type: "felt" },
      { name: "proposalId", type: "felt" },
      { name: "support", type: "felt" },
    ]
  },
  primaryType: "Vote",
  domain: {
    name: "StarkDAO",
    version: "1",
    chainId: shortString.encodeShortString('SN_SEPOLIA'),
  },
  message: {
    voter: "0x0123456789abcdef",
    proposalId: "0x42",
    support: "1" 
  }
};

const dataTestVariations = [
  { description: "empty string", data: sampleData },
  { description: "small string", data: sampleDataTwo },
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

  it("should sign a known value", async () => {
   const expectedSignature = Buffer.from([
    5,  45,  59, 233,  68,  46, 147, 175, 158,  76,   7,
    25, 236,  54, 235, 204, 221, 208,  29,  65, 138, 221,
    239, 130, 196, 101,  72, 112, 150,  36, 121,  59,   5,
    128,  11, 178,  91,  23, 243, 106, 116, 103,  21,  15,
    1, 183,  94,  58, 227,  92, 108, 158, 227,  27,  46,
    234, 229, 112,  28,  91,  25,  30, 116, 231,   0
  ]);

    const buffer = Buffer.from(JSON.stringify(sampleData));
    const signature = await signer.sign(Uint8Array.from(buffer));
    const signatureBuffer = Buffer.from(signature);
    expect(signatureBuffer).toEqual(expectedSignature);
  });

  it("should verify a known value", async () => {
    const buffer = Buffer.from(JSON.stringify(sampleData));
    const signature = await signer.sign(Uint8Array.from(buffer));

    const publicKey = (signer.publicKey).toString('hex');
    const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
    const isValid = await StarknetSigner.verify(Buffer.from(hexString, 'hex'), buffer, signature);
    expect(isValid).toEqual(true);
  });
  it("should sign & verify", async () => {
    const buffer = Buffer.from(JSON.stringify(sampleData));
    const signature = await signer.sign(Uint8Array.from(buffer));

    const publicKey = (signer.publicKey).toString('hex');
    const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
    const isValid = await StarknetSigner.verify(Buffer.from(hexString, 'hex'), buffer, signature);
    expect(isValid).toEqual(true);
  });

  describe("Create & Validate DataItems", () => {
    it("should create a valid dataItem", async () => {
      const data = JSON.stringify(sampleData);
      const tags = [{ name: "Hello", value: "Bundlr" }];
      const item = createData(data, signer, { tags });
      await item.sign(signer);
      expect(await item.isValid()).toBe(true);
    });

    describe("With an unknown wallet", () => {
      it("should sign & verify an unknown value", async () => {
        const randSigner = new StarknetSigner(provider, myAddressInStarknet, PrivateKey);
        const buffer = Buffer.from(JSON.stringify(sampleData));
        const signature = await randSigner.sign(Uint8Array.from(buffer));

        const publicKey = (signer.publicKey).toString('hex');
        const hexString = publicKey.startsWith("0x") ? publicKey.slice(2) : publicKey;
        const isValid = await StarknetSigner.verify(Buffer.from(hexString, 'hex'), buffer, signature);
        expect(isValid).toEqual(true);
      });
    });

    describe("and given we want to create a dataItem", () => {
      describe.each(tagsTestVariations)("with $description tags", ({ tags }) => {
        describe.each(dataTestVariations)("and with $description data", ({ data }) => {
          it("should create a valid dataItem", async () => {
            const item = createData(JSON.stringify(data), signer, { tags });
            await item.sign(signer);
            expect(await item.isValid()).toBe(true);
          });

          it("should set the correct tags", async () => {
            const item = createData(JSON.stringify(data), signer, { tags });
            await item.sign(signer);
            expect(item.tags).toEqual(tags ?? []);
          });

          it("should set the correct data", async () => {
            const item = createData(JSON.stringify(data), signer, { tags });
            await item.sign(signer);
            expect(item.rawData).toEqual(Buffer.from(JSON.stringify(data)));
          });
        });
      });
    });
  });
});
