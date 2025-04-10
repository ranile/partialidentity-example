window.global ||= window;
import {
  Ed25519KeyIdentity,
  DelegationIdentity,
  PartialDelegationIdentity,
  DelegationChain,
  PartialIdentity,
} from "@dfinity/identity";
import { HttpAgent, Actor } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";

const signIdentity = Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32));

// Construct a partial identity to point to so the auth client knows to construct a partial delegation identity
const partial = new PartialIdentity(
  signIdentity.getPublicKey(),
);

console.log("signing key", signIdentity.getPrincipal().toText());
console.log("partial identity", partial.getPrincipal().toText());

const authClient = await AuthClient.create({
  identity: partial,
});

const identity = authClient.getIdentity();
console.log("authClient identity is the partial identity", identity.getPrincipal().toText());

document.querySelector('#login').addEventListener('click', ()=>authClient.login({
    identityProvider: "https://identity.ic0.app",
    onSuccess: () => handle(),
    onError: (error) => reject(error),
  }));


async function handle() {
// Identity after login is a PartialDelegationIdentity
  const identity = authClient.getIdentity();
  const delegation = identity.delegation;

  console.log("delegation",delegation);
  

//   Construct identity from the delegation and the original signing key
  const delegationIdentity = new DelegationIdentity(
    signIdentity,
    delegation,
  );
  console.log("Logged in, reproducible principal", delegationIdentity.getPrincipal().toText());


//   Make a call to a live canister
  const idlFactory = ({ IDL }) => {
    return IDL.Service({ 'whoami' : IDL.Func([], [IDL.Principal], ['query']) });
  };
  const canisterId = "ivcos-eqaaa-aaaab-qablq-cai";
    const agent = HttpAgent.createSync({ identity: delegationIdentity, host: "https://icp-api.io" });
    const actor = Actor.createActor(idlFactory, {
      agent,
      canisterId,
    });
    const principal = await actor.whoami();
    console.log("whoami", principal.toText());
}
