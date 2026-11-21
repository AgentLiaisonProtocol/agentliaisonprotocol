// The walkthrough on the overview page: four exchanges from the specification's Appendix A, step by step.
// tools/site/lib/walkthrough.mjs renders it (tools/site/README.md, "The walkthrough").
//
// Every sentence here restates Appendix A, or the specification section a step names; nothing adds
// behaviour the appendix doesn't describe. Every object is taken at build time from a named example of the
// specification ({ example }) or from a vector file ({ vector, path }); `mark` lists the members the step
// talks about. Teal (side a) is the sender's side and orange (side b) the other person's side; side c is
// anyone else (an impostor, a stranger).
//
// Inline markup in text: `code`, and [text](target) with target glossary:<id>, spec:<section> or a site path.
//
// A scenario: { id, title, short (tab label), appendix, intro, sides: { a, b, c?, cKey? },
//   nodes: [{ id, label (one or two lines), side: "a" | "b" | "shared" | "c", kind: "agent" | "broker" |
//            "person" | "doc", col, row, span? }],
//   hops: [{ id, from, to, refused?, link?, offset? }],
//   steps: [{ title, text: [one to three sentences], a?, b?, c?, cLabel?, refs: [sections], hops?, nodes?,
//            objects?: [{ label, example | vector + path, mark, note? }] }] }

const SENDER_VECTOR = "vectors/policy/sender.json";
const LEDGER_VECTOR = "vectors/ledger/matching-ledgers.json";
const MEETING_VECTOR = "vectors/threads/meeting-commit.json";

export const walkthroughs = [
  {
    id: "one-organization",
    title: "A request inside one organization",
    short: "Inside one organization",
    appendix: "A.1",
    intro: "`example.org` runs one broker for all its people. Ana, an analyst, asks Lee, a leader, for a briefing.",
    sides: { a: "Ana", b: "Lee" },
    nodes: [
      { id: "ana", label: ["Ana’s", "agent"], side: "a", kind: "agent", col: 0, row: 0 },
      { id: "broker", name: "example.org’s broker", label: ["example.org’s broker", "home to Ana and Lee"], side: "shared", kind: "broker", col: 1, row: 0, span: 2 },
      { id: "lee", label: ["Lee’s", "agent"], side: "b", kind: "agent", col: 3, row: 0 },
    ],
    hops: [
      { id: "send", from: "ana", to: "broker", offset: -1 },
      { id: "refused", from: "ana", to: "broker", refused: true, offset: 1 },
      { id: "deliver", from: "broker", to: "lee" },
    ],
    steps: [
      {
        title: "Ana’s agent asks for a briefing",
        text: [
          "Ana’s agent is connected in [client mode](glossary:client-mode): through one connector, with no work from its vendor. It calls the tool `alp_send` with a request for Lee in the [scope](glossary:scope) `alp.briefing/1`, a named kind of work with its own fields.",
          "The request goes to Ana’s [home broker](glossary:home-broker), the one broker that speaks for her, which here is Lee’s home broker too.",
        ],
        a: "Her agent asks about the Q4 launch staffing plan: one question, with a summary as the answer.",
        b: "Nothing has reached Lee or his agent.",
        refs: ["A.1", "12.1.3"],
        hops: ["send"],
      },
      {
        title: "The broker checks Ana’s side first",
        text: [
          "Before anything leaves Ana’s side, the broker runs the sender-side checks: no kill switch applies, and her agent is a client allowed for this scope.",
          "The organization’s private policy puts Ana in `analysts` and Lee in `leaders`, and its default relationship lets analysts ask leaders for briefings. That covers the request and every field in it, the body passes the scope’s schema, and the check for sensitive data finds nothing.",
        ],
        a: "Her broker checks every field before anything leaves.",
        b: "Lee doesn’t have to approve: the organization’s default relationship approves on his behalf.",
        refs: ["A.1", "6.6", "6.4"],
        nodes: ["broker"],
        objects: [
          { label: "the vector case for this request", vector: SENDER_VECTOR, path: "cases.name=allowed through the organization's default relationship", mark: ["expected"], note: "the case named “allowed through the organization’s default relationship”" },
        ],
      },
      {
        title: "It signs an envelope",
        text: [
          "The broker signs the request as an [envelope](glossary:envelope), the signed unit that crosses between brokers.",
          "The envelope names Ana, her agent and Lee, the relationship it travels under (`grant`) and the broker’s decision.",
        ],
        a: "`from` names Ana’s agent, `agent-a`, with the attestation and class the broker knows from the organization’s list, never from the agent.",
        b: "`to` names Lee, and `aud` the broker that serves him.",
        refs: ["8.2", "8.5"],
        nodes: ["broker"],
        objects: [
          { label: "the signed envelope", example: "a1_envelope", mark: ["from", "to", "aud", "grant", "decision"] },
        ],
      },
      {
        title: "Lee’s agent gets the request",
        text: [
          "Because the broker is home for both people, it answers the first receiving checks (steps 0 to 6) from its own records, runs Lee’s checks (steps 7 to 11), and delivers.",
          "Lee’s agent finds the request in its inbox, with what the broker verified kept apart from what Ana’s agent wrote, which is marked as content to treat as data, never as instructions.",
        ],
        b: "His agent sees the sender as the broker verified it: Ana, through her agent `agent-a`.",
        refs: ["A.1", "12.2.4", "12.1.6"],
        hops: ["deliver"],
      },
      {
        title: "What is refused: a confidential amount",
        text: [
          "Had Ana’s agent added an amount to the request (`context.amount`, 1,250,000 USD), the broker would have refused it before anything left Ana’s side.",
          "The amount is labeled `confidential.financial`, and the organization’s rule `fin-1` allows that label only to its finance group.",
        ],
        a: "Her agent gets an `org_policy` error that names the rule and the amount’s two fields.",
        b: "Nothing reaches Lee or his agent.",
        refs: ["A.1", "6.6"],
        hops: ["refused"],
        objects: [
          { label: "the vector case for this refusal", vector: SENDER_VECTOR, path: "cases.name=financial figure blocked by org rule fin-1 before anything leaves", mark: ["draft.body.context", "expected"], note: "Appendix A.1 cites it" },
        ],
      },
    ],
  },

  {
    id: "two-organizations",
    title: "A request between two organizations",
    short: "Between two organizations",
    appendix: ["A.2", "A.4"],
    intro: "Pat works at `partner.example`, which has its own broker. Pat has a relationship with Lee, at `example.org`, for status updates (`alp.status/1`).",
    sides: { a: "Pat", b: "Lee", c: "Impostors", cKey: "brokers that don’t speak for the sender" },
    nodes: [
      { id: "rogue", name: "rogue.example", label: ["rogue.example", "(not listed)"], side: "c", kind: "broker", col: 0, row: 0 },
      { id: "hosted", name: "hosted.example.net", label: ["hosted.example.net", "(listed for guest)"], side: "c", kind: "broker", col: 1, row: 0 },
      { id: "doc", label: ["example.org’s", "domain document"], side: "b", kind: "doc", col: 2, row: 0 },
      { id: "pat", label: ["Pat’s", "agent"], side: "a", kind: "agent", col: 0, row: 1 },
      { id: "patb", label: ["Pat’s", "home broker"], side: "a", kind: "broker", col: 1, row: 1 },
      { id: "leeb", label: ["Lee’s", "home broker"], side: "b", kind: "broker", col: 2, row: 1 },
      { id: "patl", label: ["Pat’s", "ledger"], side: "a", kind: "doc", col: 1, row: 2 },
      { id: "leel", label: ["Lee’s", "ledger"], side: "b", kind: "doc", col: 2, row: 2 },
    ],
    hops: [
      { id: "lookup", from: "patb", to: "doc" },
      { id: "agent", from: "pat", to: "patb" },
      { id: "envelope", from: "patb", to: "leeb", offset: -1 },
      { id: "receipt", from: "leeb", to: "patb", offset: -1 },
      { id: "ledger-a", from: "patb", to: "patl" },
      { id: "ledger-b", from: "leeb", to: "leel" },
      { id: "same", from: "patl", to: "leel", link: true },
      { id: "rogue", from: "rogue", to: "patb", refused: true },
      { id: "hosted", from: "hosted", to: "patb", refused: true },
    ],
    steps: [
      {
        title: "Pat’s broker looks up Lee’s home broker",
        text: [
          "Lee’s address is on `example.org`, so Pat’s broker reads `example.org`’s [domain document](glossary:domain-document): a public file at `https://example.org/.well-known/alp.json` that names the brokers that speak for the domain’s people and pins their keys.",
          "Lee isn’t listed by name, so the broker listed for everyone else (`\"*\"`) is his [home broker](glossary:home-broker).",
        ],
        a: "Pat’s broker learns where to post (that broker’s `inbox`) and the key thumbprint `example.org` pins for it (`jkt`).",
        b: "Because the document lists `\"*\"` rather than names, it doesn’t publish Lee’s address.",
        refs: ["A.2", "4.2", "4.5"],
        hops: ["lookup"],
        objects: [
          { label: "example.org’s domain document", example: "a2_doc", mark: ["brokers.0.id", "brokers.0.inbox", "brokers.0.jkt", "brokers.0.principals"] },
        ],
      },
      {
        title: "The signed envelope crosses",
        text: [
          "Pat’s broker posts the [envelope](glossary:envelope), signed for Pat, to the federation inbox of Lee’s broker. Its `aud` names Lee’s broker as the one it is for.",
        ],
        a: "Pat’s agent, `agent-c`, wrote the request; Pat’s broker signed it.",
        b: "Nothing reaches Lee’s agent until his broker has checked it.",
        refs: ["A.2", "12.2.1", "8.5"],
        hops: ["agent", "envelope"],
        objects: [
          { label: "the signed envelope", vector: LEDGER_VECTOR, path: "envelope", mark: ["from", "aud", "origin_broker", "broker_sig"], note: "the envelope of Appendix A.2" },
        ],
      },
      {
        title: "Lee’s broker checks it and answers with a receipt",
        text: [
          "Lee’s broker checks the envelope against `partner.example`’s domain document (steps 0 to 6), then against Lee’s [grant](glossary:grant), his rules for Pat (steps 7 to 11).",
          "It accepts the envelope and answers with a [receipt](glossary:receipt): its signed answer to a delivered envelope, which carries the envelope’s hash.",
        ],
        a: "Pat’s broker gets a signed receipt with `status` `accepted`.",
        b: "The receipt also carries `ledger_hash`, the hash of the entry Lee’s broker wrote in Lee’s ledger.",
        refs: ["A.2", "12.2.4", "10.4"],
        hops: ["receipt"],
        objects: [
          { label: "the receipt", example: "a2_receipt", mark: ["receipt.envelope_hash", "receipt.status", "receipt.ledger_hash"] },
        ],
      },
      {
        title: "Both ledgers hold the same hash",
        text: [
          "Each home broker keeps a [ledger](glossary:ledger) for each of its people: an append-only, hash-chained record the person can read. Lee’s entry records the envelope as received; Pat’s records the receipt.",
          "Both entries carry the same `envelope_hash`, and Pat’s also carries the hash of Lee’s entry, so either side can check the other’s record.",
        ],
        a: "Pat’s entry holds the receipt’s hash (`receipt_hash`) and the hash of Lee’s entry (`counterparty_ledger_hash`).",
        b: "Lee’s entry records the scope, the one field that crossed (`/body/subject`) and the decision.",
        refs: ["11.5", "11.2"],
        hops: ["ledger-a", "ledger-b", "same"],
        objects: [
          { label: "Lee’s ledger entry", example: "a2_lee", mark: ["disclosed", "envelope_hash", "hash"] },
          { label: "Pat’s ledger entry", example: "a2_pat", mark: ["envelope_hash", "receipt_hash", "counterparty_ledger_hash"] },
        ],
      },
      {
        title: "An impostor broker is refused",
        text: [
          "An envelope claims to come from Ana at `example.org`, but `rogue.example` signed it, and it is posted to Pat’s broker.",
          "`example.org`’s document doesn’t list `rogue.example`, so Pat’s broker finds no key `example.org` pins for it and answers with an unsigned `broker_not_authorized` error.",
        ],
        a: "Pat’s agent never sees anything.",
        c: "Pat’s broker answers it with an unsigned error.",
        cLabel: "The impostor",
        refs: ["A.4", "12.2.4"],
        hops: ["rogue"],
        objects: [
          { label: "the impostor’s envelope", example: "a4_rogue", mark: ["from.address", "origin_broker"] },
        ],
      },
      {
        title: "A listed broker can’t speak for someone else",
        text: [
          "`example.org`’s document also lists `hosted.example.net`, but only for `guest@example.org`.",
          "The same envelope signed by that broker passes the first checks and fails step 6, also with `broker_not_authorized`, this time in a signed receipt with `status` `refused`.",
        ],
        a: "Pat’s broker refuses the envelope.",
        refs: ["A.4", "12.2.4"],
        hops: ["hosted"],
      },
    ],
  },

  {
    id: "connection-request",
    title: "Someone new asks to connect",
    short: "Someone new asks to connect",
    appendix: "A.5",
    intro: "Pat, at `partner.example`, has no relationship with Lee for status updates. Pat’s agent asks to connect.",
    sides: { a: "Pat", b: "Lee", c: "A stranger", cKey: "a stranger" },
    nodes: [
      { id: "pat", label: ["Pat’s", "agent"], side: "a", kind: "agent", col: 0, row: 0 },
      { id: "patb", label: ["Pat’s", "home broker"], side: "a", kind: "broker", col: 1, row: 0 },
      { id: "leeb", label: ["Lee’s", "home broker"], side: "b", kind: "broker", col: 2, row: 0 },
      { id: "lee", label: ["Lee’s", "agent"], side: "b", kind: "agent", col: 3, row: 0 },
      { id: "patp", name: "Pat, on Pat’s page", label: ["Pat, on", "Pat’s page"], side: "a", kind: "person", col: 1, row: 1 },
      { id: "leep", label: ["Lee, on", "his page"], side: "b", kind: "person", col: 2, row: 1 },
      { id: "stranger", label: ["a stranger’s", "broker"], side: "c", kind: "broker", col: 3, row: 1 },
    ],
    hops: [
      { id: "ask", from: "pat", to: "patb" },
      { id: "pat-approves", from: "patp", to: "patb" },
      { id: "request", from: "patb", to: "leeb", offset: -1 },
      { id: "receipt", from: "leeb", to: "patb", offset: -1 },
      { id: "show", from: "leeb", to: "leep" },
      { id: "lee-approves", from: "leep", to: "leeb", offset: 1 },
      { id: "stranger", from: "stranger", to: "leeb", refused: true },
    ],
    steps: [
      {
        title: "Pat approves asking",
        text: [
          "Pat’s agent calls `alp_request_connection`. Pat approves the request on Pat’s own [web view](glossary:web-view), the small web page each broker serves its people, and seals Pat’s own terms.",
        ],
        a: "Pat, not Pat’s agent, approves sending the request.",
        b: "Nothing has reached Lee yet.",
        refs: ["A.5", "6.2.1"],
        hops: ["ask", "pat-approves"],
      },
      {
        title: "A connection request goes to Lee",
        text: [
          "Pat’s broker sends a control envelope: a signed envelope that carries a connection request.",
          "It names the scope Pat asks for (`alp.status/1`), a purpose, the name Pat’s broker gives for Pat and a short note.",
        ],
        a: "The request asks for status updates only (`purpose`: `status_updates`).",
        b: "It goes to Lee, not to his agent.",
        refs: ["A.5", "6.2.1", "8.6"],
        hops: ["request"],
        objects: [
          { label: "the connection request", example: "a5_control", mark: ["type", "body", "note"] },
        ],
      },
      {
        title: "Lee’s broker shows Lee, not his agent",
        text: [
          "Lee’s broker runs its checks, applies its limits on connection requests and answers with an `accepted` receipt, as it would for any request that passed its first checks.",
          "It shows Lee a digest entry: Pat’s verified address, the name Pat’s broker gives, the scope, the purpose and the note, as plain, untrusted text.",
        ],
        a: "Pat’s broker gets the same `accepted` receipt as for any request that passed those checks.",
        b: "Lee sees who is asking and why, on his own page. His agent sees nothing.",
        refs: ["A.5", "6.2.2"],
        hops: ["receipt", "show"],
      },
      {
        title: "Lee accepts, on his own terms",
        text: [
          "Lee approves with a fresh, strong sign-in and seals his own terms: his [grant](glossary:grant), which says what may cross between him and Pat.",
          "His broker sends a connection response accepting `alp.status/1`, in reply to the request, and Pat’s broker activates Pat’s grant.",
        ],
        a: "Pat’s grant becomes active.",
        b: "Only now can messages from Pat reach Lee’s agent, and only within what Lee allowed.",
        refs: ["A.5", "6.2.3", "6.3"],
        hops: ["lee-approves", "receipt"],
      },
      {
        title: "A stranger who skips the request",
        text: [
          "A message that a lax broker sends without any relationship takes the same path as a contact attempt.",
          "Lee’s broker refuses it with `not_accepted` and shows Lee only who tried to reach him, never the body.",
        ],
        b: "Lee sees who tried to reach him, never what they wrote.",
        c: "Lee’s broker refuses it with `not_accepted`.",
        cLabel: "The stranger",
        refs: ["A.5", "6.2.5"],
        hops: ["stranger", "show"],
      },
    ],
  },

  {
    id: "meeting",
    title: "Agreeing on a meeting",
    short: "Agreeing on a meeting",
    appendix: "A.6",
    intro: "Ana and Lee, both at `example.org`, agree on a meeting. Their agents negotiate; only Ana and Lee can make it binding.",
    sides: { a: "Ana", b: "Lee" },
    nodes: [
      { id: "ana", label: ["Ana’s", "agent"], side: "a", kind: "agent", col: 0, row: 0 },
      { id: "broker", label: ["example.org’s", "broker"], side: "shared", kind: "broker", col: 1, row: 0 },
      { id: "lee", label: ["Lee’s", "agent"], side: "b", kind: "agent", col: 2, row: 0 },
      { id: "anap", label: ["Ana, on", "her page"], side: "a", kind: "person", col: 0, row: 1 },
      { id: "leep", label: ["Lee, on", "his page"], side: "b", kind: "person", col: 2, row: 1 },
    ],
    hops: [
      { id: "ana-out", from: "ana", to: "broker", offset: -1 },
      { id: "to-ana", from: "broker", to: "ana", offset: -1 },
      { id: "to-lee", from: "broker", to: "lee", offset: 1 },
      { id: "lee-out", from: "lee", to: "broker", offset: 1 },
      { id: "ana-ratifies", from: "anap", to: "broker" },
      { id: "lee-ratifies", from: "leep", to: "broker" },
    ],
    steps: [
      {
        title: "Ana’s agent proposes two times",
        text: [
          "In the scope `alp.meeting/1`, Ana’s agent proposes two slots to Lee’s agent for a 30-minute video call.",
          "Proposing commits no one: binding commitments need both people to ratify the agreed terms first.",
        ],
        a: "Nothing is booked yet.",
        b: "Lee’s agent receives the proposal.",
        refs: ["A.6", "7.8"],
        hops: ["ana-out", "to-lee"],
        objects: [
          { label: "the proposal", vector: MEETING_VECTOR, path: "objects.propose", mark: ["type", "body.slots"], note: "Appendix A.6 cites it" },
        ],
      },
      {
        title: "Lee’s agent accepts the second",
        text: [
          "Lee’s agent accepts the second slot. That fixes the terms, and their hash, `terms_hash`, names them from then on.",
        ],
        a: "Ana’s agent receives the acceptance, with the agreed terms.",
        b: "Agreeing commits no one yet: Lee still has to ratify.",
        refs: ["A.6", "9.3"],
        hops: ["lee-out", "to-ana"],
        objects: [
          { label: "the acceptance", vector: MEETING_VECTOR, path: "objects.accept", mark: ["type", "body.terms", "terms_hash"], note: "Appendix A.6 cites it" },
        ],
      },
      {
        title: "Both people ratify",
        text: [
          "[Ratification](glossary:ratification) is a person’s own approval, on their home broker, of agreed terms before anything binding happens.",
          "Ana and Lee each review the terms on their [web view](glossary:web-view) and ratify them. Ana’s record names the same `terms_hash` and how she approved (`webauthn-uv`, a passkey with user verification).",
        ],
        a: "Her broker signs her ratification record.",
        b: "Lee ratifies on his own page too.",
        refs: ["A.6", "9.4", "12.5.3"],
        hops: ["ana-ratifies", "lee-ratifies"],
        objects: [
          { label: "Ana’s ratification record", example: "a6_ratification", mark: ["terms_hash", "address", "method"] },
        ],
      },
      {
        title: "Lee’s record goes to Ana’s side",
        text: [
          "Lee’s ratification record travels in an `ack` with `status` `ratified`, sent by Lee himself, not by an agent.",
        ],
        a: "Ana’s side now holds both people’s records.",
        b: "Lee’s record shows that he approved with a single sign-on step-up (`sso-stepup`).",
        refs: ["A.6", "9.4"],
        hops: ["lee-ratifies", "to-ana"],
        objects: [
          { label: "Lee’s ack, with his record", vector: MEETING_VECTOR, path: "objects.ack_ratified_lee", mark: ["from", "body.status", "body.ratification"], note: "Appendix A.6 cites it" },
        ],
      },
      {
        title: "Ana’s agent commits",
        text: [
          "Ana’s agent commits, carrying the same `terms_hash` and the hashes of both people’s records in `ratifications`.",
          "Then it books the meeting in Ana’s own calendar.",
        ],
        a: "Her agent can commit only once her broker holds both records for the same terms, and the commit lets it act only in Ana’s own tools, within those terms.",
        b: "Lee’s agent receives the commit as information; anything it does in Lee’s tools needs Lee’s own grants.",
        refs: ["A.6", "9.5"],
        hops: ["ana-out", "to-lee"],
        objects: [
          { label: "the commit", vector: MEETING_VECTOR, path: "objects.commit", mark: ["type", "terms_hash", "ratifications"], note: "Appendix A.6 cites it" },
        ],
      },
    ],
  },
];
