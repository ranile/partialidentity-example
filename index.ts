window.global ||= window;
import {
  Ed25519KeyIdentity,
  DelegationIdentity,
  PartialDelegationIdentity,
  DelegationChain,
  PartialIdentity,
  Ed25519PublicKey,
} from "@dfinity/identity";
import {
  HttpAgent,
  Actor,
  bufFromBufLike,
  DerEncodedPublicKey,
  PublicKey,
  fromHex,
  toHex,
  ActorMethod,
} from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { Principal } from "@dfinity/principal";

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
    //   Make a call to a live canister
    const idlFactory = ({ IDL }) => {
      return IDL.Service({ whoami: IDL.Func([], [IDL.Principal], ["query"]) });
    };
    const canisterId = "ivcos-eqaaa-aaaab-qablq-cai";
    const agent = HttpAgent.createSync({
      identity: this.#identity,
      host: "https://icp-api.io",
    });
    const actor = Actor.createActor<_SERVICE>(idlFactory, {
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
