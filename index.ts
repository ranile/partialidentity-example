(window as any).global ||= window;
import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
  Ed25519PublicKey,
  isDelegationValid,
  JsonnableDelegationChain,
  PartialDelegationIdentity,
  PartialIdentity,
} from "@dfinity/identity";
import {
  Actor,
  ActorMethod,
  bufFromBufLike,
  DerEncodedPublicKey,
  fromHex,
  HttpAgent,
  PublicKey,
  requestIdOf,
  toHex,
} from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { Principal } from "@dfinity/principal";
import { initSync, verifyIcSignature } from '@dfinity/standalone-sig-verifier-web';

const IC_ROOT_KEY = fromHex('814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae')

async function initWasm() {
  const wasm = await fetch("https://cdn.jsdelivr.net/npm/@dfinity/standalone-sig-verifier-web@1.0.0/standalone_sig_verifier_web_bg.wasm")
    .then(r => r.blob())
    .then(r => r.arrayBuffer())

  const mod = await WebAssembly.compile(wasm)
  return initSync(mod)
}

await initWasm()

class Backend {
  authenticate(delegationChain: JsonnableDelegationChain, challenge: Uint8Array, signed: Uint8Array) {
    verifyChallenge(delegationChain, challenge, new Uint8Array(signed))
    // TODO: reproducible principal
    alert("Challenge verified");

  }
}

const backend = new Backend()

interface _SERVICE {
  whoami: ActorMethod<[], Principal>;
}

class NativeApp {
  signIdentity: Ed25519KeyIdentity = Ed25519KeyIdentity.fromSecretKey(
    bufFromBufLike(new Uint8Array(32))
  );

  #identity: DelegationIdentity | undefined;

  getPublicKey() {
    return this.signIdentity.getPublicKey();
  }

  async whoami() {
    const whoamiResult = document.querySelector("#whoami-result")!;
    // Make a call to a live canister
    const canisterId = "ivcos-eqaaa-aaaab-qablq-cai";
    const agent = HttpAgent.createSync({
      identity: this.#identity,
      host: "https://icp-api.io",
    });
    const actor = Actor.createActor<_SERVICE>(({ IDL }) => {
      return IDL.Service({whoami: IDL.Func([], [IDL.Principal], ["query"])});
    }, {
      agent,
      canisterId,
    });
    const principal = await actor.whoami();
    if (principal.toString() === Principal.anonymous().toString()) {
      whoamiResult.innerHTML = "You are logged out (anonymous principal)";
    } else {
      whoamiResult.innerHTML = `Your principal is: ${principal.toString()}`;
    }
  }

  constructor() {
    const whoamiButton = document.querySelector("#whoami")!;
    const whoamiResult = document.querySelector("#whoami-result")!;
    whoamiButton?.addEventListener("click", () => {
      whoamiResult.innerHTML = "Loading...";
      this.whoami();
    });

    const verifyChallengeButton = document.querySelector("#verify-challenge")!;
    verifyChallengeButton.addEventListener("click", async () => {
      this.verifyChallenge()
    })
  }

  makeDelegationIdentity(delegationString: string) {
    const delegation = DelegationChain.fromJSON(JSON.parse(delegationString));
    const delegationIdentity = DelegationIdentity.fromDelegation(
      this.signIdentity,
      delegation
    );
    this.#identity = delegationIdentity;
    return delegationIdentity;
  }

  getIdentity() {
    return this.#identity;
  }


  async verifyChallenge() {
    if (!this.#identity) {
      throw new Error('No identity found');
    }
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const signed = await this.#identity.sign(challenge.buffer)

    backend.authenticate(
        this.#identity.getDelegation().toJSON(),
        challenge,
        new Uint8Array(signed),
    )
  }
}

const nativeApp = new NativeApp();

class Frontend {
  partialIdentity: PartialIdentity;
  authClient: AuthClient;

  static constructPartialIdentity(publicKey: DerEncodedPublicKey) {
    const pubKey: PublicKey = Ed25519PublicKey.fromDer(publicKey);
    return new PartialIdentity(pubKey);
  }

  private constructor(
    partialIdentity: PartialIdentity,
    authClient: AuthClient
  ) {
    this.authClient = authClient;
    this.partialIdentity = partialIdentity;

    document?.querySelector?.("#login")?.addEventListener("click", () =>
      authClient.login({
        identityProvider: "https://identity.ic0.app",
        onSuccess: () => this.handle(this.authClient),
        onError: (error) => {
          throw new Error(error);
        },
      })
    );
  }

  static async create(hexEncodedPublicKey: string) {
    const partialIdentity = this.constructPartialIdentity(
      fromHex(hexEncodedPublicKey)
    );
    const authClient = await AuthClient.create({
      identity: partialIdentity,
    });
    return new Frontend(partialIdentity, authClient);
  }

  async handle(authClient: AuthClient) {
    // Identity after login is a PartialDelegationIdentity
    const identity = authClient.getIdentity() as PartialDelegationIdentity;
    const delegation = identity.delegation;

    const delegationString = JSON.stringify(delegation.toJSON());
    nativeApp.makeDelegationIdentity(delegationString);
  }
}

const frontend = await Frontend.create(toHex(nativeApp.getPublicKey().toDer()));

const domainSeparator = new TextEncoder().encode('\x1Aic-request-auth-delegation');

const verifyChallenge = (delegationChainJSON: JsonnableDelegationChain, challenge: Uint8Array, signedChallenge: Uint8Array) => {
  const delegationChain = DelegationChain.fromJSON(delegationChainJSON);

  // Verify if the frontend key pair signed the challenge
  verifyIcSignature(challenge, signedChallenge, new Uint8Array(delegationChain.delegations.slice(-1)[0].delegation.pubkey), new Uint8Array(IC_ROOT_KEY));

  // Verify if delegation chain data is valid e.g. not expired or too long
  if (!isDelegationValid(delegationChain) || delegationChain.delegations.length > 20) {
    throw new Error('Invalid delegation')
  }

  // Verify the whole chain of signatures one by one
  for (let index = 0; index < delegationChain.delegations.length; index++) {
    const {delegation, signature} = delegationChain.delegations[index];
    const challenge = new Uint8Array([
      ...domainSeparator,
      ...new Uint8Array(requestIdOf({...delegation})),
    ]);
    const publicKey = index === 0
      ? delegationChain.publicKey
      : delegationChain.delegations[index - 1].delegation.pubkey;
    verifyIcSignature(challenge, new Uint8Array(signature), new Uint8Array(publicKey), new Uint8Array(IC_ROOT_KEY));
  }
}