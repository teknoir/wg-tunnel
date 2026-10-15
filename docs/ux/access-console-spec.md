# Access console: interaction spec

**Status:** D-UX deliverable for ZTNA phase 2 (`plans/ztna-phase2.md`, sections 1 to 6, updated for "Rev 2 decisions"), 2026-10-14. Draft for Anders's review. **Rev 3 (this version):** the trusted SSH host key comes only from the admin action "Trust this host key", never from the SSH tunnel; the bold comparison now compares SSH host-key fingerprints; four new states were added (section 3.6).
**Prototype:** `access-console.html` in this folder. It is one static file, and the only external resource is JetBrains Mono from Google Fonts. Open it in a browser and use the small "Prototype" switcher at the bottom right (two selects: state, and view as admin or member), or open it with a hash: `#active`, `#waiting`, `#waitingok`, `#waitingwg`, `#forced`, `#unattested`, `#duplicate`, `#unavail`, `#unavailkey`, `#mismatch`, `#revoked`, `#offline`, `#off`, `#stale`, `#loading`, `#dialog`, `#dialogbad`, `#dialogks`. Add `member` to view the page as a non-admin, for example `#active,member`.
**Implements:** W5 (backstage). It replaces `DeviceWireGuardContent.tsx` on branch `robot`.

## Rev 4: zero-touch device key (supersedes the host-key flow of sections 3.1 to 3.7)

**Requirement (Anders, 2026-10-15):** "The device bootstrap process is a trusted process and should create what is needed for all Teknoir platform services to a device including WireGuard. It should not require any hands-on steps to connect a bootstrapped device with for example WireGuard. If any secrets still have to be exchanged they have to do so through MQTT, the primary channel, managed securely by the device-controller." Design: `plans/ztna-rev3-zero-touch.md`; wire contract: `pkg/api` ("Device key (rev 3)") and `pkg/devicekey`.

The trust anchor is no longer an SSH host key an admin compares and trusts, but a per-device **device key** that the trusted bootstrap installs or that device-controller seals to the device's RSA key and ships over MQTT. The agent signs its enrollment with it and the hub activates the identity. Nobody pastes or compares a fingerprint, so the host-key comparison UI, the paste box and the "Trust this host key" actions are gone. Where sections 3.1 to 3.7 and the prototype say "host key", read "device key", and apply the changes below. The wire names `trustedHostKey`, `attestedHostKey` and `duplicateHostKey` are kept.

| Rev 3 (host key) | Rev 4 (device key) |
|---|---|
| Waiting for a first trust (3.3): paste `ssh-keygen -lf`, "Trust host key and activate" | **Waiting for device:** no pin yet and a device key is set; no action. **Delivering device key over MQTT (since t):** the key was sent and the hub has not seen it yet; no action. |
| Auto-activated (3.1), "Update trusted host key" | **Active, Automatic, device key.** The label names the source: bootstrap, virtual device or MQTT. For MQTT it reads "legacy bootstrap: as strong as the device RSA key during delivery". Admins get **Rotate device key** (reason required) in place of "Update trusted host key". |
| Host key mismatch (3.4) | **Device key mismatch**, red, shown only after delivery is confirmed (an attestation by another key than the one device-controller set). |
| Unattested enrollment (3.6.1), Duplicate host key (3.6.3) | Kept. "Duplicate host key" is relabelled **Duplicate device key**. |
| Forced manual after a compromise (3.6.2) | A cleared compromised or health flag no longer forces manual approval: it bumps the generation, **rotates the device key over MQTT** and re-activates automatically. The state stays only for an admin who ticks "require manual approval next" (`manual-next`) or sets `activation=manual`. |
| Automatic verification unavailable (3.6.4), "no ed25519 host key", `ssh-keygen -A` | Removed. The kind `unavailable-key` is gone; `unavailable-old` is renamed **Agent update rolling out** (an agent without `device-key-v1`). |
| Manual approval of one identity (3.7), "Approve identity only" | Kept for `manual`, `forced` and `unattested` states only; no longer offered next to a pending first trust. |

**Facts on the card:** device-key fingerprint, source and set-at, delivered and confirmed times, WireGuard identity fingerprint, activated at and by (`approval`, `device-key`, or `host-key` for entries from before rev 3), enrollment epoch and generation, and replacements. A **replacement** happens when the device is offline, lost its identity and enrolls again with the device key; the card shows "Identity replaced N times, last at t" and the fingerprint that was replaced. While the device is online the same enrollment is a conflict, as before.

**Actions:** `trust-host-key` returns 410; `approve-identity` is allowed only in the manual, forced and unattested states; `clear-flags` gets "require manual approval next"; new `rotate-device-key` (admin, reason) and `register-device-key` (editor, used by `tnctl bootstrap`). The prototype `access-console.html` still shows the rev 3 states and is not updated.

---

## 0. Design plan

### Subject, audience, job
- **Subject:** remote access to one edge device over WireGuard. There are two paths: direct (peer-to-peer) and relayed through the hub.
- **Audience:** teamspace operators and admins. They are technical, in a hurry, and often in the middle of an incident. They know SSH and Kubernetes, but they should not have to know WireGuard internals.
- **Primary job:** answer three questions at a glance, then let the operator act.
  1. Can I trust this device right now?
  2. How do I reach what's running on it?
  3. Who is connected?

### Tokens: existing HUD only, nothing new
| Name | Hex | Role in this page |
|---|---|---|
| `bg` | `#000000` | Page. The backdrop glows (blue top right, purple bottom left) and the 40px grid stay as they are in `HudContentShell` |
| `panel` | white at 5% to 2% over bg, 1px `rgba(255,255,255,.10)` border | Every panel. Radius is 0. The corner ticks carry the accent |
| `green` `#1DB954` | | Active, match, ssh service, direct path |
| `blue` `#3B61BF` | | Internal (k3s service), neutral information, focus of the selected row. Used as a fill or border only, never as small text, because its contrast on black is 3.6:1 |
| `purple` `#9B357D` | | External service (address on the device network). Used as a fill or border only, at 3.0:1 |
| `orange` `#ED6D36` | | Needs attention: waiting for approval, settings an admin must look at |
| `red` `#FA4E4E` | | Mismatch, revoked, compromised, destructive actions, error toasts |
| `yellow` `#E0AD1B` | | Stale data, device offline |
| `off` `#E0DED9` / `silver` `#808080` | | Body text and secondary text. Silver on black is 5.3:1 |

- **Accessibility fix to the product precedent:** Tunneling's "Open tunnel" puts black text on purple, which is 3.0:1. On this page, text on blue and purple fills is white (5.6:1 and 6.4:1), and text on green stays black (9:1).

### Type
- **Font:** a single mono family, `ABCDiatypeMono` Regular and Medium, as in the product. The prototype uses JetBrains Mono as a stand-in.
- **Scale:** it follows the product's existing steps, so it does not introduce a new rhythm.

| Size | Use |
|---|---|
| 10px, uppercase, 0.12em tracking, silver | Field and stat labels. This is the existing convention. No new eyebrows are added |
| 12px / 18px | Body and helper text |
| 13px | Values and table cells |
| 15px, Medium | Panel headings in sentence case (as in `HudEmptyState`) and card names |
| 20px, Medium | Fingerprint groups and the verdict line. They exist only in the Identity panel |
| 26px, bold | Shell title (existing) |

- **Numbers:** all are tabular, which is free with a mono font.

### Layout
The console stays inside the existing entity page chrome and tab bar. Content max width is 1400px with a 16px grid gap.

```
┌ HudContentShell header (accent = state colour) ──────────────────────────────┐
│ [key] DEVICE · RTX2000-…       STATE        PATH          SESSIONS ACTIVATION │
│       WireGuard access         Active       Direct (LAN)  2        Automatic  │
│       Reach services…                                   ● Live, updated 2 s ago│
└──────────────────────────────────────────────────────────────────────────────┘
┌ Identity (full width, the bold element) ─────────────────────────────────────┐
│ ▌Activated automatically                                                      │
│ ▌Signed with the trusted SSH host key (trusted by <admin> on <date>).         │
│                                                                               │
│  Trusted host key     [eb+w][4rp2][udRH][YG3b] … [W80]    │ Trusted by        │
│                         │     │     │     │        │      │ Attested          │
│  Signed by device     [eb+w][4rp2][udRH][YG3b] … [W80]    │ Conflicts         │
│  11 of 11 groups match                 What this proves ▸ │ WG identity ⧉     │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Services ─────────────────────────────────────────────────── [+ Add service] ┐
│ ┌ ssh (green) ─────┐ ┌ grafana (blue) ───┐ ┌ openclaw (purple) ┐             │
│ │ target, protocol │ │ k3s service       │ │ address on device │             │
│ │ [Open terminal]  │ │ [Open]            │ │ [Open]            │             │
│ │ $ tnctl ssh … ⧉  │ └───────────────────┘ └───────────────────┘             │
│ └──────────────────┘ ┌ postgres (blue) ──┐ ┌ camera (purple) ──┐             │
│                      │ $ tnctl port-fw ⧉ │ │ $ tnctl port-fw ⧉ │             │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Live sessions (8 col) ─────────────────────┐ ┌ Connection (4 col) ────────────┐
│ User  Service  Path  Since  Data  [End]    │ │ Hub link, RTT, last handshake  │
│ …                                          │ │ NAT: direct possible           │
└────────────────────────────────────────────┘ │ ⏻ WireGuard access             │
┌ Trust (8 col) ─────────────────────────────┐ │ ⏻ Direct connections (P2P)     │
│ No flags. [Mark compromised] [Health …]    │ │ ◧ Activation: Automatic|Manual │
│ Admin: [Clear flags] [Reset enrollment]    │ │ ⏻ Web terminal                 │
└────────────────────────────────────────────┘ └────────────────────────────────┘
```

- **Alignment:** everything is left-aligned. Numbers in the table are right-aligned. The header stats are right-aligned, as on the Overview page.
- **Order:** the order follows the three questions: trust, then reach, then who. In the active state, the operator's eye goes from the header to Services in one move, because the Identity panel is short (about 200px).

### The one bold element
- **What it is:** the fingerprint comparison in the Identity panel.
  - Two fingerprints sit stacked as 4-character groups at 20px, in one column per group.
  - A vertical connector joins each pair of groups. Green means sealed, a red "≠" with red-tinted groups means broken, and a dashed silver line means nothing to compare yet.
  - Above them is a verdict line at 20px with a 4px state-coloured bar.
- **What it compares (Rev 3):** always **SSH host-key fingerprints** (SHA256 of the ed25519 host-key blob, the same format in the contract, the controller and the UI). The WireGuard identity fingerprint is never in the bold comparison, except in the manual-approval states (3.7), where it is the only thing an admin can compare. It sits in the side column otherwise.
  - **Active:** "Trusted host key" over "Signed by device".
  - **Waiting for a first trust:** "Signed by device" (the attested host key from the enrollment attestation) over "On the device" (what the admin pastes from `ssh-keygen -lf`).
- **Why it works:** it turns a 43-character eyeball check into a shape you read in one glance: one unbroken row of seals, or not.
- **Motion:** this is the page's only orchestrated motion. When the comparison result changes (on load, on a new state, or when the operator pastes a fingerprint), the connectors resolve left to right with a 35ms stagger. Reduced motion turns it off.
- **Everything else stays quiet:** the existing panels, labels and buttons are unchanged.

### Review against the brief and the generic defaults (what I changed before building)
1. **Removed a top "alert band"** for waiting and mismatch. It duplicated the header state and the Identity verdict, and it would have been a second loud element. The header stat and the Identity panel (first on the page) carry it.
2. **Made Identity full width.** It was 8 columns next to Connection. Eleven group columns need about 800px, and the bold element should not be squeezed.
3. **Mismatch story corrected.** I first drew a mismatch as "two groups differ". A different host key changes the hash in every group, so a real mismatch shows 0 of 11 matching. Per-group diffs are useful for the **manual paste** comparison (typos, truncation, a stale log line).
   - The verdict always states the count and never treats a near match as almost fine, because near matches are what a vanity-key attack looks like.
4. **No new uppercase.** Panel headings are sentence case (15px Medium, like `HudEmptyState`), not new tracked-out caps. The 10px uppercase field labels stay, because the product uses them everywhere.
5. **Buttons are sentence case,** following the current WireGuard tab rather than Tunneling's uppercase "OPEN TUNNEL". Open question 3 asks about aligning Tunneling too.
6. **No numbered sections, no middle-dot meta strings, no arrows on buttons, no shadows.** The only glow is the existing icon-box glow from the shell.
   - The supertitle `DEVICE · <name>` is the shared `HudContentShell` component, so it is left as it is.

---

## 1. Information architecture

The tab is renamed from "WireGuard (ZTNA)" to **"WireGuard"** (see open question 1). The shell title is "WireGuard access" and the subtitle is "Reach services on this device without exposing it to the internet".

| Region | Data source | Who sees it | Who acts |
|---|---|---|---|
| Header strip | `GET …/devices/:ns/:name/ztna` (live CR status, annotations and hub live status) | everyone with device read | none |
| Identity | same, `status.wireguard.activation`, `identityFingerprint`, `approvedFingerprint`, `trustedHostKey` (annotation `ztna.teknoir.org/trusted-host-key`, who, when), attestation, `forceManual`, duplicate-key device, conflicts | everyone | Trust this host key, Approve identity, Update trusted host key, Reset enrollment: admins. Keep blocked, Mark compromised: device editors |
| Services | `ztna.teknoir.org/services` annotation, `status.wireguard.services[].url` | everyone | Add, remove: **admins only** (the annotation guard allows only the Backstage SA, which runs the admin check). Open, copy: everyone with access |
| Live sessions | hub live status (`clientSessions[]`) | everyone (user emails are teamspace members) | End session: admins |
| Connection | hub live status (device session, RTT, last handshake, NAT class), annotations `ztna.teknoir.org/p2p`, activation mode, enable, web terminal | everyone | admins |
| Trust | flags annotations, last change (who, when, reason) | everyone | Mark compromised / health failed: device editors. Clear flags, Reset enrollment: admins |

"Admin" means what `GET …/ztna/permissions` returns. That is the same SubjectAccessReview the backend enforces. The UI never infers admin from catalog permissions.

## 2. Header strip

| Stat | Values (colour) | Rule |
|---|---|---|
| State | Active (green), Waiting for approval (orange), Blocked (red, host key mismatch, unattested enrollment or conflicts), Revoked (red), Device offline (yellow), Off (silver) | Priority, highest first: Off > Revoked > Blocked > Device offline > Waiting for approval > Active |
| Path | Direct (LAN), Direct, Relayed, Relayed (strict NAT), Through hub, or a dash | The best path among live P2P sessions. When the state is Active and there are no P2P sessions, it shows what a new tnctl session would get, based on the device NAT class: "Direct" or "Relayed (strict NAT)", with the tooltip "Expected path for a new session". With P2P off, it shows "Through hub". In every other state it shows a dash, because nobody can connect |
| Sessions | count | Live client sessions, web and tnctl |
| Activation | Automatic (green), Approved manually (green), No trusted host key (orange), Manual, forced (orange), Duplicate host key (orange), Manual only (orange), Host key mismatch (red), Unattested enrollment (red), Enrollment conflict (red), a dash | From `status.wireguard.activation`. It says *why*, so it never repeats the State value: State says "Waiting for approval", and Activation says "No trusted host key" |

- **Accent:** the header icon box and ticks take the State colour.
- **Live line** (right of the header, under the stats):
  - **Live:** "Live, updated 2 s ago", with a pulsing green dot (static under reduced motion).
  - **Stale:** "Stale, last update 2 min ago. Retrying in 5 s.", in yellow with no pulse, plus a **Refresh** button.
  - **Paused:** while the tab is hidden, polling stops and the line reads "Paused while the tab is hidden".

## 3. Identity panel

The heading is **Identity**. On the right sits an "Activation: Automatic / Manual" read-only chip, linked to the Connection panel.

### 3.1 Auto-activated (`verifiedBy: ssh-host-key`)
- **Verdict (green):** "Activated automatically"
- **Line under it:** "The device signed its new identity with the trusted SSH host key (trusted by anders.aslund@teknoir.ai on 12 Oct at 09:14)."
- **Comparison:** the rows are "Trusted host key" and "Signed by device". Both are host-key fingerprints. All groups are sealed. The summary reads "11 of 11 groups match" and "Host key SHA256:eb+w4rp2… (ed25519)".
- **Facts column:**

| Label | Content |
|---|---|
| Trusted by | admin and date of the "Trust this host key" action |
| Attested | relative time, for example "4 min ago" |
| Enrollment conflicts | number. Zero shows silver, one or more shows orange with "auto-activation paused" |
| WireGuard identity | short fingerprint plus a copy button. It is the identity that was activated, kept out of the bold comparison on purpose |
| Enrollment | "#2, 15:44" |

- **Admin action:** a quiet text button, "Update trusted host key", under the comparison (see 3.4 for the dialog). Members do not see it.
- **There is no "anchor source" any more.** The trusted key comes from one place only: an admin ran "Trust this host key". The SSH tunnel and anything seen through it play no part, because an attacker holding an RSA key could forge it while the device is offline.
- **Disclosure "What this proves":**
  > Only root on the device can read its SSH host key, so a signature from it shows that the enrolling software runs on the same machine an admin checked when trusting the key. It doesn't protect you if someone already has root on the device. Devices cloned from one image share host keys, so Teknoir refuses automatic activation when two devices trust the same key. In those cases, switch activation to Manual.

### 3.2 Approved manually (`verifiedBy: approval`)
The comparison is not shown, because nothing was compared by the system. The verdict is green, "Approved manually", with the line "Approved by anders.aslund@teknoir.ai on 3 Oct. This device has no trusted host key, so its next re-enrollment waits for approval again." The facts column shows "Trusted host key: None". Admins see a text button "Trust this host key", which opens the paste flow from 3.3.

### 3.3 Waiting for approval, no trusted host key yet
There are two separate admin actions, and the page keeps them apart:

| Action | What it does |
|---|---|
| **Trust this host key** | Sets annotation `ztna.teknoir.org/trusted-host-key` on the device to the SHA256 fingerprint of its ed25519 SSH host key. From then on, a re-enrollment signed by that key activates automatically. It does not approve the pending identity by itself |
| **Approve identity** | Manual approval of one WireGuard identity, as today. It trusts nothing for later |

The primary action combines them, because that is what nearly every admin wants.

- **Verdict (orange):** "Waiting for approval"
- **Line under it:**
  > No SSH host key is trusted for this device yet. Compare the host key it signed its enrollment with against the key on the device itself, then trust it. After that, every re-enrollment signed by that key activates automatically.
- **Comparison (bold element):**
  - Top row: "Signed by device". It is the attested host key, taken from the enrollment attestation.
  - Bottom row: "On the device". It shows dashed empty groups until the admin pastes.
  - The WireGuard identity fingerprint is **not** here. It is in the side column, under "WireGuard identity".
- **Order follows the task:** comparison, then the command, then the paste field, then the actions.
- **Command with copy button:** "On the device, run this and paste what it prints:" `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. The `.pub` file is world-readable, so no sudo is needed.
- **Paste field:** labelled "Paste the output of ssh-keygen". The output looks like `256 SHA256:<43 chars> root@host (ED25519)`.
  - The field **extracts the `SHA256:` token** (the 43 characters after the prefix, up to the next space). Key size, user, host and the `(ED25519)` suffix are ignored.
  - It also accepts a bare `SHA256:…` value, the 43 characters alone, or a log line.
  - The summary shows what was read: "Read from your paste: 43 of 43 characters". A short read points to a truncated paste.
  - The comparison updates as the admin types.
- **Actions (admin):**
  - **Trust host key and activate** (primary green). It does both: sets the trusted host key and approves the current WireGuard identity. It is enabled only when all 11 groups match. The enabled hint reads "Trusts this host key for this device and approves its WireGuard identity (right)."
  - **Trust host key only** (outlined). It records the key and leaves the identity waiting. It has the same enabling rule.
  - Disabled hints: "Paste the output from the device to enable trusting." when empty, or "Trusting needs every group to match." plus the summary "3 groups differ. Check for a typo or copy the line again."
  - Success toast: "Host key trusted. Identity approved. The device connects within a few seconds. Its next re-enrollments activate automatically."
  - No confirmation dialog. The comparison is the confirmation.
- **No shell access to the device:** a disclosure, "No shell access to the device?", explains that **Approve identity only** is possible by comparing the agent log instead (3.7), and that the next re-enrollment will wait again because no host key is trusted.
- **Members** see the comparison and "Ask a teamspace admin to trust this host key. Send them this page." No buttons.
- **The old "turn on the SSH tunnel to skip the comparison" hint is removed.** The tunnel can no longer create trust.

### 3.4 Host key mismatch (attestation does not match the trusted key)
- **Verdict (red):** "Host key mismatch. Access is blocked."
- **Line under it:**
  > The device signed its enrollment with a different SSH host key than the one an admin trusted on 12 Oct. Either the host keys were changed (an OS reinstall or image rebuild), or another machine is using this device's credentials.
- **Comparison:** "Trusted host key" over "Signed by device". All groups are red with "≠". The summary reads "0 of 11 groups match. A different key changes every group. Never accept a partial match."
- **Character marks:** the differing characters are underlined only when at least one group matches, which is the typo case (waiting state, or a truncated paste). In a real mismatch every character would be underlined, which adds only noise.
- **Actions, in this order:**

| Action | Who | Effect |
|---|---|---|
| **Keep blocked** | device editors, default, outlined | Acknowledges and keeps the device blocked. The toast reads "Device stays blocked." |
| **Mark compromised** | device editors, red outlined | Asks for a reason (see section 7) |
| **Reset enrollment** | admin | Confirmation dialog |
| **Update trusted host key** | admin, red text button, last | Dialog: "Trust the new host key?" |

- **Update trusted host key dialog body:**
  > Do this only if you changed this device's SSH host keys yourself, for example by reinstalling the OS. On the device, run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` and check that it prints the fingerprint shown here. If you are not sure, keep it blocked and check the device first.
- **Dialog fields:** the new fingerprint (the device's attested key, shown as the groups, read-only), the same paste field as 3.3 (the action enables only on a full match), and a required reason saved in the audit log. Buttons are Cancel and **Trust new host key** (red).
- **Members** see "Ask a teamspace admin to reset the enrollment or update the trusted host key."
- **Conflicts:** when the epoch has conflicts, the panel shows "2 enrollment conflicts since the last reset. Auto-activation is paused until an admin resets enrollment." This also applies in state 3.1.

### 3.5 Revoked, offline, off
- **Revoked:** the verdict is red, "Access revoked", and the line reads "Marked compromised by anders.aslund@teknoir.ai 14 min ago: 'Unknown process on port 8443'. After an admin clears the flag, the next identity needs manual approval (see 3.6.2)." The comparison stays visible but greyed (opacity 0.5), because the identity itself is still the last known one.
- **Device offline:** the verdict keeps the last activation result. A yellow line reads "The device hasn't been connected to the hub since 15:02 (12 min ago). Values below are its last known state."
- **Off:** the whole content area is an empty state. The heading is "WireGuard access is off for this device", followed by:
  > Turn it on to reach SSH and the services you add here through an encrypted tunnel, without opening ports on the device.

  The button is **Turn on WireGuard** (admin). Non-admins see "Ask a teamspace admin to turn it on."

### 3.6 Safety states added by Rev 2
Each has its own header Activation value, and the State stat shows what the operator can expect. The rule that keeps them calm: **red means "probably not the device"; orange means "needs a person"**.

| Header State | Header Activation | Colour | Section |
|---|---|---|---|
| Blocked | Unattested enrollment | red | 3.6.1 |
| Waiting for approval | Manual, forced | orange | 3.6.2 |
| Waiting for approval | Duplicate host key | orange | 3.6.3 |
| Waiting for approval | Manual only | orange | 3.6.4 |

#### 3.6.1 Unattested enrollment from a capable agent (red)
- **When:** the agent advertises host-key attestation (`attest-v1`) but this enrollment has no attestation. A genuine agent always attests, so this is likely not the device.
- **Verdict (red):** "Unattested enrollment. Likely not this device."
- **Line under it:**
  > The agent on this device always signs its enrollment with the SSH host key, but this enrollment arrived with no signature. A genuine agent would have signed it, so something else is probably using this device's credentials. Access is blocked. If the real device enrolls, its signed enrollment replaces this one by itself.
- **Comparison:** "Trusted host key" over "Signed by device", with dashed empty groups. The summary reads "Nothing signed. Nothing to compare." and "An unsigned enrollment never matches, whatever it presents."
- **Facts:** Attested "Never, this enrollment", and Agent "Offers attestation, did not use it" in orange.
- **Actions:** **Keep blocked** (default), **Reset enrollment** (admin), **Mark compromised** (red outlined). Members see "Ask a teamspace admin to reset the enrollment." There is no approve action here. Approving would defeat the point of the attestation.
- **Why "replaces itself":** a valid attestation by the trusted key displaces an unattested pin. Without that, an attacker could squat the pin and lock the real device out.

#### 3.6.2 Forced manual after a compromise (orange)
- **When:** an admin cleared a compromised or health flag. For the next identity (one generation), activation is manual even though the host key matches.
- **Verdict (orange):** "Manual approval required this time"
- **Line under it, in plain words:**
  > An admin cleared a compromised flag on 14 Oct at 16:02. This device's host key still matches the trusted one, but that is not enough now. If the device was compromised, whoever had access could also use its host key, so a match proves little. A person must approve the next identity. After that, automatic activation resumes.
- **Main comparison:** the manual flow of 3.7, because that is what the admin can act on. The host-key result is not buried: the facts column leads with "Host key: Matches the trusted key" (green), and shows who cleared the flag and when.
- **Under the actions:** "Applies once, to this enrollment only. The activation setting stays on Automatic."
- **Connection panel:** the Activation setting stays on Automatic. A line under it reads "Forced manual once: clearing the compromised flag requires a person to approve the next identity."
- **Header:** State "Waiting for approval", Activation "Manual, forced".

#### 3.6.3 Duplicate host key (orange)
- **When:** the same host key is already trusted on another device, for example a cloned image. Automatic activation is refused for every device that shares it.
- **Verdict (orange):** "Automatic activation refused: duplicate host key"
- **Line under it:**
  > The same SSH host key is trusted on jetson-orin-lab-3. Devices cloned from one image share host keys, so the key can't tell them apart. Approve this identity by hand. To get automatic activation back, generate new SSH host keys on one of the two devices and trust the new key.
- **Which device:** the other device's name is a link in the verdict and in the facts column ("Also trusted on", orange). The link goes to its WireGuard tab. If the viewer cannot read that device, the name shows without a link.
- **Main comparison and actions:** the manual flow (3.7).

#### 3.6.4 Automatic verification unavailable (orange)
- **Title:** "Automatic verification unavailable: <reason>". The reason is one of:
  - **agent too old:** "The agent on this device is too old to sign its identity with the SSH host key (it does not offer host-key attestation). Update the agent to turn automatic activation on. Until then, approve each identity by hand."
  - **no ed25519 host key:** "This device has no ed25519 SSH host key, so the agent has nothing to sign with. Generate one on the device (`ssh-keygen -A`) to turn automatic activation on. Until then, approve each identity by hand."
- **Facts:** Trusted host key "Not possible yet", plus the Agent version and Host key rows that explain the reason.
- **Main comparison and actions:** the manual flow (3.7). There is no "Trust this host key" here, because there is no key to trust.
- Not red: this is a known limitation, not a sign of attack.

### 3.7 Manual approval flow (one WireGuard identity)
Used by 3.3 after "Approve identity only", and by 3.6.2, 3.6.3 and 3.6.4. It is the phase 1 flow, with the same order: comparison, command, paste, action.
- **Comparison:** "Presented to Teknoir" (the pinned WireGuard identity) over "From the device log". This is the only place where a WireGuard fingerprint is the bold comparison, because the SSH host key cannot help here.
- **Command:** `sudo kubectl logs deploy/wg-agent | grep 'device identity'`. The agent Deployment is `wg-agent` in the device's default namespace, per device-controller `plugin_wireguard/agent.go`.
- **Paste field:** the same extractor as 3.3 (log line, `SHA256:…` or bare value).
- **Action:** **Approve identity** (admin, green), enabled only when every group matches. Disabled hints: "Paste the device's fingerprint to enable approval." and "Approval needs every group to match."
- **Members:** "Ask a teamspace admin to approve this identity. Send them this page."
- **Toast:** "Identity approved. The device connects within a few seconds." Approve sends the fingerprint shown on screen (taken from the live route, not the catalog), so a device that re-enrolls while the admin compares produces an error toast and not a wrong approval.
- **Way back:** in the waiting state a text link, "Compare the host key instead", returns to 3.3.

### 3.8 Accessibility of the comparison
- **Screen readers:**
  - The comparison is a `figure` with an `aria-label`, for example "Fingerprint comparison, 11 of 11 groups match".
  - The marks are `aria-hidden`.
  - A visually hidden list reads each group as "Group 4: eb+w, match".
- **Not colour alone:** match and mismatch use glyph and line style as well as colour. A match is a solid line, a mismatch is "≠" plus an underline on the differing characters, and pending is a dashed line.
- **Text:** the groups are selectable text. Copying the row copies the full `SHA256:` fingerprint without spaces, because the groups are visual only and the separators are CSS gaps.

## 4. Services

- **Panel:** the heading is **Services**, with a count. The right side has **Add service** (outlined, **admins only**). Members see "Only teamspace admins can add or remove services." in its place, and no remove icons. The empty card says "Ask a teamspace admin to add services."
- **Note under the grid (admins):** "Only teamspace admins can add or remove services. Targets are checked when you add them and again by the device on every connection."
- **Grid:** 3 columns at 1200px and wider, 2 columns from 768px up, 1 column below.
- **Order:** ssh first (fixed), then by kind (internal, external), then by ID.

### Card anatomy (extends the Tunneling card)
- **Top line:** an accent square, the ID (15px Medium, lowercase as entered), and a kind tag on the right ("SSH", "k3s service" or "Device network", 10px label). Remove is an icon button with the tooltip "Remove service". It is not present on ssh.
- **Fields:**
  - Target: `127.0.0.1:22`, `grafana.monitoring:3000`, or `192.168.10.64:554`.
  - Protocol: "HTTP, in browser", "HTTP" or "TCP".
  - Description: optional, one line.
- **Primary action:**
  - **HTTP published in the browser:** **Open** is a full-width accent button that opens `https://wgs-<hash>.<domain>` in a new tab. Under it is the URL in silver with a copy button.
  - **TCP or unpublished HTTP:** a command block `$ tnctl port-forward --wireguard <device> <id>` with a copy button.
  - **Port hint:** it appears once under the grid, not on every card: "tnctl port-forward prints the local port it listens on. Put a port before the service ID to choose it, for example `8080:postgres`."
  - **Commands wrap:** command blocks wrap instead of truncating, because the device name is long and the service ID at the end is the part that matters.
  - **ssh:** **Open terminal** (green, web terminal; hidden when the web terminal is off), plus a command block with `tnctl ssh --wireguard <device>`.
- **Accent per kind:** ssh is green, internal (k3s service) is blue, external (device network) is purple. Button text on blue and purple is white.

### States
- **Unavailable** (revoked, offline, waiting, mismatch): cards stay visible so the operator can still see what exists.
  - **Buttons:** Open and the commands are disabled.
  - **Explanation:** one line above the grid, which depends on the state.
    - Waiting (all variants): "Services open once the device identity is approved."
    - Mismatch: "Services stay closed while the host key does not match." Unattested: "Services stay closed while this enrollment is blocked."
    - Revoked: "Access is revoked. Services are unreachable until an admin clears the flags."
    - Offline: "The device is offline. Services are unreachable until it reconnects."
  - **Copy:** copying a command stays possible, because people prepare scripts.
- **Pending:** a service added but not yet in the policy shows a silver "Applying…" tag and no Open. It typically clears in under 10 s, after the next policy push.
- **Empty (only ssh exists):** a dashed-tick empty card sits next to ssh.
  - Text: "Add a service to reach a web app or a port on this device. Use a k3s service for apps running in the device's cluster, or an address for things on its network, like a camera."
  - Button: **Add service**.
- **Remove:** a confirmation dialog.
  - Title: "Remove openclaw?"
  - Body: "People using it lose access, and its browser address stops working. Open sessions to this service end."
  - Buttons: Cancel and **Remove service** (red).
  - Toast: "openclaw removed." The real error text is shown on failure.

### Add service dialog (560px Modal)
- **Title:** "Add service". The product `Modal` renders it in uppercase, which is its existing convention.
- **Intro line (always):** "Only teamspace admins can add services. The device checks every target again on each connection." The dialog is never reachable for members, and the backend returns 403 if it is called anyway.
- **Disclosure "What can be a target" (above the buttons):** "No loopback addresses, except the device's SSH service. No link-local addresses (169.254.0.0/16, fe80::). No control-plane ports of the device (6443, 10250, 10255, 2379, 2380, 10257, 10259). A k3s service must have a cluster IP and cannot be in kube-system or be default/kubernetes."
- **Behaviour:** page scroll is locked while the dialog is open.
- **Kind picker:** two option tiles (radio group, arrow keys move between them).
  - **k3s service:** "An app in the device's cluster, reached by its Service name."
  - **Device network address:** "Something on the device's network, like a camera or a local web UI."
- **For a k3s service:**
  - **Service picker:** a searchable list of the device's Services (from the device workloads data). Each row shows `name`, `namespace` and its ports, like `3000/TCP http`.
    - Empty list: "No Services found on this device. Deploy an app first, or use a device network address."
    - Loading: "Loading the device's services…"
    - Error: shows the backend message.
  - **Port:** a select of the chosen Service's ports. It is prefilled when there is only one.
- **For a device network address:**
  - **IP address:** placeholder `192.168.10.64`.
  - **Port:** placeholder `554`.
- **Shared fields:**
  - **ID:** prefilled from the Service name, editable. Helper: "Used in tnctl commands and the browser address."
  - **Protocol:** a segmented choice, HTTP or TCP. It is preselected from the port's `appProtocol` or name when known (`http`, `80`, `8080`, `3000`, `8086` mean HTTP).
  - **Publish in the browser:** a checkbox, only with HTTP and on by default. Helper: "Gives teamspace members a sign-in protected address like https://wgs-….teknoir.cloud."
  - **Description:** optional.
- **Buttons:** Cancel and **Add service** (white primary). Add service is disabled until the form is valid. After a click it shows "Adding…".
  - Success toast: "grafana added. It's ready in a few seconds."
  - Server error: the toast shows the backend message, and the field it names is marked.

**Validation messages** (inline, under the field, red, shown after blur or submit):

| Case | Message |
|---|---|
| ID empty | "Enter an ID." |
| ID invalid | "Use lowercase letters, digits and dashes, starting with a letter." |
| ID too long | "Use at most 20 characters (23 now)." |
| ID taken | "This device already has a service called grafana." |
| ID `ssh` | "ssh is reserved for the device's SSH service." |
| IP is a host name | "Enter an IP address. Services don't use host names, so a changed DNS record can't redirect them." |
| IP invalid | "Enter an IPv4 address like 192.168.10.64." |
| Port out of range | "Enter a port from 1 to 65535." |
| Duplicate target | "grafana already reaches grafana.monitoring:3000." This is a warning, not an error. The service can still be added |
| No service picked | "Pick a k3s service." |
| Loopback IP (127.0.0.0/8) | "Loopback addresses (127.0.0.0/8) are only allowed for the device's SSH service. Use the device's network address, or a k3s service." |
| Link-local IP (169.254.0.0/16) | "Link-local addresses (169.254.0.0/16) aren't allowed. They include cloud metadata endpoints." |
| Node IP on a control-plane port | "Port 10250 on 192.168.10.20 is a Kubernetes control-plane port of this device and can't be exposed (6443, 10250, 10255, 2379, 2380, 10257, 10259)." Shown full width under the IP and port row, because the port column is too narrow for it |
| k3s service in kube-system | "Services in kube-system can't be exposed. They belong to the device's control plane." |
| default/kubernetes | "default/kubernetes is the Kubernetes API server and can't be exposed." |
| ExternalName or CNAME service | "legacy-db is an ExternalName Service. Only Services with a cluster IP in this device's k3s can be exposed." |

- **Disallowed k3s services stay in the picker,** greyed, tagged "Not allowed" and selectable, so the admin sees the reason instead of wondering where the service went. The message appears under the picker and Add service stays disabled.
- **Same rules on the server:** device-controller validates on write and the agent validates on every dial. The client messages above are for the common cases, and the backend's `{message, field}` is shown verbatim for anything else (for example a node IP the browser does not know).
- **Loopback targets:** the sample "openclaw" service now targets its device-network address (192.168.10.30:31789), because a loopback target is no longer allowed. An app that listens only on 127.0.0.1 must be moved to a network address or put behind a k3s Service.

## 5. Live sessions

- **Panel:** the heading is **Live sessions** with the count.
- **Table columns:**
  - User: email, with "you" appended in silver for the viewer's own sessions.
  - Service: the ID with the kind accent square.
  - Client: "tnctl" or "Browser".
  - Path: a chip.
  - Since: relative time, with the absolute time as a `title`.
  - Data: down and up, for example "4.1 MB ↓ 220 kB ↑". Right-aligned.
  - End: admins only.
- **Path chips:**
  - Direct (LAN) and Direct: green outline.
  - Relayed: blue outline.
  - Relayed (strict NAT): blue outline with a tooltip: "Both networks block direct connections. Traffic goes through the hub, encrypted end to end."
  - Through hub: silver. This covers browser and web terminal sessions.
- **End session** (admin): a red text button per row ("End"), not a boxed button. Boxed red buttons in every row were too loud.
  - Confirmation: "End anders@…'s ssh session? Their connection drops now. They can reconnect if they still have access."
  - Buttons: Cancel and **End session** (red).
  - Toast: "Session ended."
- **Empty:** "No one is connected. Sessions appear here within 5 seconds of someone opening a service."
- **Revoked:** "No sessions. All sessions ended when access was revoked."
- **Offline:** "No sessions while the device is offline."
- **Order:** most recent first. Bytes update on every poll. A changed row does not animate.

## 6. Connection panel

- **Device link:**
  - Connected: "Connected to the hub. 38 ms, last handshake 4 s ago."
  - Not connected: "Not connected since 15:02." (yellow)
- **Direct connections:**
  - When the device NAT class is known: "Possible from most networks." for endpoint-independent NAT, or "Unlikely: the device is behind strict NAT. Sessions will be relayed." for symmetric NAT.
- **Switches** (admin; non-admins see them read-only with the line "Only teamspace admins can change these."):
  - **WireGuard access:** on or off. Turning it off opens a confirmation:
    > Turn off WireGuard access? Everyone connected loses access now, and the device stops accepting WireGuard connections. The SSH tunnel on the Tunneling tab is not affected.
  - **Direct connections (peer to peer):** default on. Helper: "Off: all traffic goes through the hub, which checks access on every connection. Slower, but access changes apply at once." Turning it off moves live P2P sessions to the hub path without dropping them.
  - **Activation:** a segmented control, Automatic or Manual. Helper: "Automatic: a new identity activates by itself when the device signs it with the SSH host key an admin trusted. Manual: an admin approves every new identity."
  - **Web terminal:** on or off. Helper: "Lets people open an SSH terminal in the browser."
- **Switch colour:** a switch that is on is off-white, not green. Green on this page means "verified or healthy", and a switch is only a setting.
- **Optimistic switches:** a switch shows its new position at once with a small "Saving…" label. It reverts on failure, and the toast shows the backend's message.

## 7. Trust panel

- **Accent:** the ticks are red when any flag is set, and silver-grey (`#3A3A3A`) otherwise. Orange is not used here: when no flags are set there is nothing to attend to.
- **No flags:** "No flags set. Last change: flags cleared by anders.aslund@teknoir.ai on 12 Oct ('Testing')."
- **Flags set:** red lines such as "Compromised: marked by … 14 min ago. 'Unknown process on port 8443'."
- **Actions:**

| Action | Who | Reason field | Consequence (in the confirmation) |
|---|---|---|---|
| Mark compromised | device editors | **Required.** Shown to admins and in the audit log | "Blocks WireGuard access to this device now and ends all sessions. The device keeps running. An admin must clear the flag to restore access." |
| Mark health check failed | device editors | Required | "Blocks WireGuard access until an admin clears the flag. Use this when the device fails a check you rely on." |
| Clear flags | admins | none | "Restores WireGuard access if the identity is still approved. Sessions do not resume by themselves. The next identity needs manual approval, even if the host key matches." (forced manual, see 3.6.2) |
| Reset enrollment | admins | none | "Forgets this device's WireGuard identity. The trusted host key stays. The device enrolls again within a minute. With Automatic activation and a signature by the trusted host key, it activates without you. Otherwise it waits for approval." |

- **Button styles:**
  - Destructive buttons are red, as the product rule since `83dc35c2` requires. Mark compromised and Mark health check failed are red outlined, and their confirm buttons are red filled.
  - Clear flags is the primary (white) action when flags are set.
  - Reset enrollment is outlined.
- **Visibility by state:** Clear flags is rendered only when a flag is set. While flagged, the two Mark buttons are hidden, because the device is already blocked.
- **Admin-only actions:** for non-admins they are not rendered. Instead the panel shows one line: "Clearing flags and resetting enrollment need a teamspace admin."

## 8. Errors, loading, polling

- **First load:** skeleton rows in each panel (no spinners), with the header stats as dashes. If the request takes longer than 10 s: "Still loading. The hub may be slow to answer."
- **Polling:**
  - `GET …/ztna` runs every 5 s while the tab is visible (`document.visibilityState`).
  - After a failure, it backs off to 10 s, 20 s and then 30 s. It resets on success.
  - Polling stops when the tab is hidden and resumes immediately with a fetch.
- **Stale data:** after 2 failed polls, the live line turns yellow (see section 2) and one toast appears. Further failures don't repeat the toast.
  - Toast example: "Couldn't refresh: hub status returned 503 (hub internal API not reachable). Showing what was known 2 min ago."
- **Toasts:**
  - **Errors:** always contain the backend's message verbatim after a short lead. For example: "Couldn't approve: the device re-enrolled while you were comparing. It now presents SHA256:Rb…/8. Compare again." No error toast says "administrators only" unless the backend returned 403. The 403 text is "You need to be a teamspace admin to approve identities."
  - **Successes:** use the same verb as the button. "Approve identity" leads to "Identity approved". "End session" leads to "Session ended".
  - **Placement:** toasts appear top centre, at the top of the viewport over the app bar. That is Backstage `AlertDisplay`'s default. They must never cover the console header, because the header state is what the operator checks after an error. The first prototype pass put them under the tab bar, where they hid the State stat. Errors stay until dismissed. Successes go after 5 s.
- **Writes:** writes always refetch `…/ztna` before resolving the UI, so no state snaps back.

## 9. Keyboard, focus, accessibility

- **Tab order:**
  1. header Refresh
  2. Identity (paste field, copy, actions, disclosure)
  3. Services (Add service, then card by card: Open, copy, remove)
  4. Sessions (End buttons)
  5. Connection switches
  6. Trust actions
- **Focus:** a visible ring on everything, `2px solid #E0DED9` with a 2px offset. It is not removed for mouse users who use the keyboard (`:focus-visible`).
- **Switches** are `button role="switch" aria-checked`. Segmented controls are `radiogroup`.
- **Dialogs:** trap focus and return it to the trigger. Escape closes them. The first field gets focus. A destructive confirmation focuses Cancel.
- **Live updates:** the header state uses `aria-live="polite"` and only announces a state change ("State: Waiting for approval"), never the per-poll refresh.
- **Reduced motion:** no scanline, no pulse, no connector stagger.
- **Contrast:** all text is at least 4.5:1, apart from 10px labels in silver on panel (about 5:1, so this passes). No text sits on blue or purple without white.

## 10. Responsive behaviour (desktop-first, down to 768px)

| Width | Layout |
|---|---|
| 1200px and wider | As in the wireframe: services in 3 columns, Sessions/Trust at 8 columns, Connection at 4 |
| 900 to 1199px | Services in 2 columns. Sessions and Trust go full width, and Connection moves under them |
| 768 to 899px | Header stats wrap under the title in a 2x2 grid. In the comparison, the row labels become a legend above the groups, and the groups wrap in units that keep each pair and its connector together. The facts column moves under the comparison. The Sessions table drops the Client column, and Data moves into the Since cell as a second line. The add-service dialog is `min(560px, 100vw - 32px)` |

The page itself never scrolls horizontally. The table sits in its own `overflow-x: auto` container as a last resort.

## 11. Admin-only summary

| Action | Admin only |
|---|---|
| Trust this host key (and Trust host key and activate), Approve identity, Update trusted host key, Clear flags, Reset enrollment, End session, Add or remove services, Activation mode switch, WireGuard access, Direct connections, Web terminal, Turn on WireGuard | yes |
| Mark compromised, Mark health check failed, Keep blocked | no (device editors) |
| Open, copy commands, read everything | no (device readers) |

The backend enforces all of these (a ValidatingAdmissionPolicy lets only the Backstage service account change `ztna.teknoir.org/*` annotations, so a notebook pod cannot bypass the admin check). Members see read-only states with copy of the form "Ask a teamspace admin to …" (trust this host key, approve this identity, reset the enrollment, add services, turn it on). The UI hides or disables controls only to avoid dead ends.

## 12. Backend needs this spec adds (for C0, W3, W4, W5)

1. **`…/ztna` response:**

   | Field | Purpose |
   |---|---|
   | `activation{mode, verifiedBy, forceManual, reason, trustedHostKey{fingerprint, by, at}, attestedHostKey, attestedAt, attestationMissing, duplicateOf[], verifyUnavailable{reason}}` | Identity panel. `trustedHostKey` and `attestedHostKey` are SHA256 fingerprints of the ed25519 host-key blob (43 characters, no prefix padding). `attestationMissing` is true only for an agent that advertises `attest-v1`. `duplicateOf` names the other devices (readable ones only) |
   | `conflicts` | Enrollment conflicts this epoch |
   | `hub{connected, rttMs, lastHandshake, natClass}` | Connection panel |
   | `sessions[{id, user, service, client, path, since, rx, tx}]` | Live sessions table |
   | `services` (with `pending`) | Service cards and the Applying… tag |
   | `flags{compromised, healthFailed, by, at, reason}` | Trust panel |
   | `fetchedAt` | Live and stale indicator |

2. **`…/ztna/permissions`:** `{admin, editor}`.
   - **Trust actions:** `POST …/ztna/trust-host-key {fingerprint, approveIdentity}` (admin). The server compares the fingerprint with the attested key and refuses a mismatch, so the UI check is a convenience.
3. **`DELETE …/ztna/sessions/:id`:** End session (admin).
4. **Device Services list:** the k3s Services for the picker (name, namespace, ports, appProtocol). The workloads data may already contain it. If not, it is a W4 item.
5. **Backend errors:** returned as `{message, field?}`, so the dialog can mark the field.

## 13. Self-critique log (prototype iterations)
Screenshots are in `/home/anders/git/ai/.playwright-mcp/ux-v1-*.png` (first pass), `ux-v2-*.png` (after fixes) and `ux-v3-*.png` (Rev 3, anchor change), at 1440x900 and 768x1024. In the headless browser the prototype was served with `python3 -m http.server`, because the Playwright MCP blocks `file:` URLs.

**Pass 1 to 2**
| Problem found | Change made |
|---|---|
| The switcher overlaid content | It is now a single row with two selects |
| Green switches competed with the green verdict | Switches that are on are off-white |
| tnctl commands were truncated and hid the service ID | Commands wrap |
| Boxed red End buttons in every row | Text buttons |
| A disabled Clear flags button showed when nothing was flagged | Hidden until a flag is set |
| The header repeated itself ("Waiting for approval" next to "Needs approval") | Activation says why, for example "No host key yet". Mismatch reads State "Blocked" and Activation "Host key mismatch" |
| Waiting showed a predicted path although nobody can connect | It shows a dash |
| The paste flow was out of task order | Command, then paste, then approve, then the skip path |
| In a real mismatch every character was underlined (noise) | Character marks only appear for near matches |
| Toasts covered the header state | Moved to the top of the viewport |
| In the revoked state the Mark buttons were redundant | Hidden while flagged, and the comparison summary is silver |

**Pass 2 to 3**
| Problem found | Change made |
|---|---|
| The port-forward hint repeated on every card | One line under the grid |
| At 768px the header stats were squeezed next to the title | They take a full-width row of 4 |
| At 768px the fingerprint groups wrapped 9 + 2 | 16px groups fit 11 in one row |
| The dialog scrolled the page (the `#dialog` hash matched the container id) | Container renamed, and page scroll locked while the dialog is open |
| The port field was misaligned when the IP error showed | Fields are top-aligned |

**Pass 3 (Rev 3, anchor change; screenshots `ux-v3-*.png`)**
| Problem found | Change made |
|---|---|
| Every "SSH tunnel" anchor source, the "turn on the SSH tunnel" skip hint and the "Seen through tunnel" label were still in the draft | Removed. The trusted key comes only from the admin action "Trust this host key" |
| The bold comparison showed WireGuard identity fingerprints while waiting, which cannot start automatic activation | It now compares host-key fingerprints (attested over pasted). The WireGuard identity moved to the side column |
| A paste of the `ssh-keygen -lf` line would have kept `root@host (ED25519)` after the key, because the first extractor stripped spaces. Caught while testing the new paste field | The extractor takes the 43 characters after `SHA256:` up to the next space. The comparison shows "Read from your paste: 43 of 43 characters" so a short paste is visible |
| One primary button could not express "trust the key" and "approve the identity" separately | Primary "Trust host key and activate" does both. "Trust host key only" and, behind a disclosure, "Approve identity only" are the separate actions |
| Forced manual and duplicate key first showed the green host-key comparison under an orange verdict, which contradicted itself | The main figure is the manual approval comparison. The host-key result is a green fact in the side column |
| The port error ("Port 10250 on 192.168.10.20 is a Kubernetes control-plane port…") wrapped into a 160px column and ran 9 lines | Target messages sit full width under the IP and port row |
| Disallowed k3s services (kube-system, kubernetes, ExternalName) would have vanished from the picker with no reason | They stay in the list, greyed and tagged "Not allowed", with the reason under the picker |
| The sample `openclaw` service targeted `127.0.0.1`, which the new rules refuse | Changed to a device-network address |
| At 768px the new manual states kept the comparison readable (11 groups in one row, legend above) | No change needed |

**Kept on purpose**
- Full-width accent Open buttons, as on Tunneling.
- The supertitle with its middle dot, which is the shared shell.
- Two red-outlined flag buttons in the calm state, following the product's "destructive is red" rule.

## 14. Open questions for Anders

1. **Tab name and Tunneling:** should the tab be called "WireGuard" (proposed), or should it be merged with Tunneling into one "Access" tab later, once the legacy tunnels are retired? The service cards are deliberately built so Tunneling can become a filter of the same grid.
2. **Trusting without pasting:** should an admin be able to trust a host key without pasting the `ssh-keygen` output, for example after comparing by phone? This draft requires the paste to match. A "Compare another way" escape is possible, but it weakens the check.
3. **Button case:** Tunneling's "OPEN TUNNEL" is uppercase, and WireGuard's buttons are sentence case. This draft uses sentence case. Should Tunneling be aligned when W5 touches it?
4. **Who may flag:** this draft lets device editors mark compromised and health failed, while clearing needs an admin. Is that the intended split?
5. **Overview and Devices list:** surface "Waiting for approval" and "Host key mismatch" as a chip there too (research U4 recommends it). Is that in scope for W5, or later?
6. **Path summary with no sessions:** the header predicts the path from the NAT class. Is a prediction acceptable there, or should it show a dash until a real session exists?
7. **Approve identity only:** this draft keeps it behind the disclosure "No shell access to the device?" in the waiting state. Is it right to offer it at all, given that it never creates the trusted host key and so keeps the device in manual mode?
8. **Who can read the duplicate device:** the "duplicate host key" state names the other device. If the viewer has no read access to it, this draft shows the name without a link. Should it hide the name and say "another device" instead?
9. **Unattested enrollment:** there is no approve action in this draft, only keep blocked, reset enrollment and mark compromised. Is an admin override wanted for agents that attest only some of the time?
10. **Forced manual copy:** "Manual, forced" in the header is terse. Is "Manual after flag" clearer for operators?
