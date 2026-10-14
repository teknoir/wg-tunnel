# Access console: interaction spec

**Status:** D-UX deliverable for ZTNA phase 2 (`plans/ztna-phase2.md`, sections 1 to 6), 2026-10-14. Draft for Anders's review.
**Prototype:** `access-console.html` in this folder. It is one static file, and the only external resource is JetBrains Mono from Google Fonts. Open it in a browser and use the small "Prototype" switcher at the bottom right (two selects: state, and view as admin or member), or open it with a hash: `#active`, `#waiting`, `#mismatch`, `#revoked`, `#offline`, `#off`, `#dialog`. Add `member` to view the page as a non-admin, for example `#active,member`.
**Implements:** W5 (backstage). It replaces `DeviceWireGuardContent.tsx` on branch `robot`.

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
│ ▌The device proved it holds the SSH host key Teknoir saw through the tunnel.  │
│                                                                               │
│  Seen through tunnel  [eb+w][4rp2][udRH][YG3b] … [W80]    │ Anchor source     │
│                         │     │     │     │        │      │ Conflicts         │
│  Signed by device     [eb+w][4rp2][udRH][YG3b] … [W80]    │ WG identity  ⧉    │
│  11 of 11 groups match                 What this proves ▸ │ Enrollment        │
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
| Identity | same, `status.wireguard.activation`, `identityFingerprint`, `approvedFingerprint`, `hostKeyAnchor`, attestation, conflicts | everyone | Approve, Update anchor, Reset enrollment: admins. Keep blocked, Mark compromised: device editors |
| Services | `ztna.teknoir.org/services` annotation, `status.wireguard.services[].url` | everyone | Add, remove: device editors. Open, copy: everyone with access |
| Live sessions | hub live status (`clientSessions[]`) | everyone (user emails are teamspace members) | End session: admins |
| Connection | hub live status (device session, RTT, last handshake, NAT class), annotations `ztna.teknoir.org/p2p`, activation mode, enable, web terminal | everyone | admins |
| Trust | flags annotations, last change (who, when, reason) | everyone | Mark compromised / health failed: device editors. Clear flags, Reset enrollment: admins |

"Admin" means what `GET …/ztna/permissions` returns. That is the same SubjectAccessReview the backend enforces. The UI never infers admin from catalog permissions.

## 2. Header strip

| Stat | Values (colour) | Rule |
|---|---|---|
| State | Active (green), Waiting for approval (orange), Blocked (red, host key mismatch or conflicts), Revoked (red), Device offline (yellow), Off (silver) | Priority, highest first: Off > Revoked > Blocked > Device offline > Waiting for approval > Active |
| Path | Direct (LAN), Direct, Relayed, Relayed (strict NAT), Through hub, or a dash | The best path among live P2P sessions. When the state is Active and there are no P2P sessions, it shows what a new tnctl session would get, based on the device NAT class: "Direct" or "Relayed (strict NAT)", with the tooltip "Expected path for a new session". With P2P off, it shows "Through hub". In every other state it shows a dash, because nobody can connect |
| Sessions | count | Live client sessions, web and tnctl |
| Activation | Automatic (green), Approved manually (green), No host key yet (orange), Host key mismatch (red), Enrollment conflict (red), a dash | From `status.wireguard.activation`. It says *why*, so it never repeats the State value: State says "Waiting for approval", and Activation says "No host key yet" |

- **Accent:** the header icon box and ticks take the State colour.
- **Live line** (right of the header, under the stats):
  - **Live:** "Live, updated 2 s ago", with a pulsing green dot (static under reduced motion).
  - **Stale:** "Stale, last update 2 min ago. Retrying in 5 s.", in yellow with no pulse, plus a **Refresh** button.
  - **Paused:** while the tab is hidden, polling stops and the line reads "Paused while the tab is hidden".

## 3. Identity panel

The heading is **Identity**. On the right sits an "Activation: Automatic / Manual" read-only chip, linked to the Connection panel.

### 3.1 Auto-activated (`verifiedBy: ssh-host-key`)
- **Verdict (green):** "Activated automatically"
- **Line under it:** "The device proved it holds the SSH host key Teknoir saw through the SSH tunnel on 12 Oct at 09:14."
  - When the anchor came from a first approval, the line reads: "…the SSH host key recorded when an admin approved it on 3 Oct."
- **Comparison:** the rows are "Seen through tunnel" (or "Recorded at approval") and "Signed by device". All groups are sealed. The summary reads "11 of 11 groups match".
- **Facts column:**

| Label | Content |
|---|---|
| Anchor source | "SSH tunnel" or "First approval" |
| Attested | relative time, for example "4 min ago" |
| Enrollment conflicts | number. Zero shows silver, one or more shows orange with "auto-activation paused" |
| WireGuard identity | short fingerprint plus a copy button |
| Enrollment | "#2, 15:44" |

- **Disclosure "What this proves":**
  > Only root on the device can read its SSH host key, so a match shows the enrolling software runs on the same machine Teknoir saw before. It does not protect you if someone already has root on the device, and devices cloned from one image share host keys. In those cases, use Manual activation.

### 3.2 Approved manually (`verifiedBy: approval`)
This state looks like 3.1. The rows are "Approved by anders.aslund@teknoir.ai" and "Presented by device", and all groups match.

### 3.3 Waiting for approval (no anchor yet)
- **Verdict (orange):** "Waiting for approval"
- **Line under it:**
  > This device has no SSH host key on record yet, so it can't prove itself automatically. Compare the fingerprint it presented with the one it prints in its log, then approve. Later re-enrollments of this device activate automatically.
- **Comparison:**
  - Top row: "Presented to Teknoir", which is the pinned identity fingerprint.
  - Bottom row: "From the device log". It shows dashed empty groups until the operator pastes.
- **Order follows the task:** the comparison (the result) comes first. Below it are, in order: the command to run on the device, the paste field, Approve, and then the way to skip the comparison.
- **Paste field:** labelled "Paste the fingerprint from the device log". It accepts the whole log line, a bare `SHA256:…` value, or the value without its prefix, and it extracts the fingerprint. The comparison updates as the operator types.
- **Hint with copy button:** "On the device, run this and copy the fingerprint it prints:" followed by the command `sudo kubectl logs deploy/wg-agent | grep 'device identity'`. The agent Deployment is `wg-agent` in the device's default namespace, per device-controller `plugin_wireguard/agent.go`.
- **Way to skip the comparison** (under Approve):
  > Or skip the comparison: turn on the SSH tunnel on the Tunneling tab. Teknoir then records the device's host key and activates it without a manual comparison.

  It links to the Tunneling tab. It is shown only when tunneling is off or has no live tunnel.
- **Approve identity** (admin, primary green). It is enabled only when every group matches.
  - The disabled hint reads "Paste the device's fingerprint to enable approval" when the field is empty, or "3 groups differ. Check for a typo or copy the line again." when it is not.
  - Non-admins see the comparison and this note instead of the button: "A teamspace admin approves new device identities. Send them this page."
- **Approve confirmation:** no dialog. The comparison is the confirmation.
  - After a click, the button shows "Approving…".
  - On success, the toast reads "Identity approved. The device connects within a few seconds." and the state turns Active on the next poll.
  - Approve sends the fingerprint shown on screen (taken from the live route, not the catalog).

### 3.4 Host key mismatch (attestation does not match anchor)
- **Verdict (red):** "Host key mismatch. Access is blocked."
- **Line under it:**
  > The device signed its enrollment with a different SSH host key than the one Teknoir saw through the tunnel on 12 Oct. Either the host keys were changed (OS reinstall, image rebuild) or a different machine is using this device's credentials.
- **Comparison:** all groups are red with "≠". The summary reads "0 of 11 groups match. A different key changes every group. Never accept a partial match."
- **Character marks:** the differing characters are underlined only when at least one group matches, which is the typo case. In a real mismatch every character would be underlined, which adds only noise.
- **Actions, in this order:**

| Action | Who | Effect |
|---|---|---|
| **Keep blocked** | default, outlined | Acknowledges and keeps the device blocked. The verdict stays, and the toast reads "Device stays blocked." |
| **Mark compromised** | red outlined | Asks for a reason (see section 7) |
| **Reset enrollment** | admin | Confirmation dialog |
| **Update anchor** | admin, red text button, last | Dialog: "Trust the new host key?" |

- **Update anchor dialog body:**
  > Do this only if you changed this device's SSH host keys yourself, for example by reinstalling the OS. Teknoir then trusts the new key and activates the device. If you are not sure, keep it blocked and check the device first.
- **Update anchor dialog fields:** a required reason, saved in the audit log. Buttons are Cancel and **Trust new host key** (red).
- **Conflicts:** when the epoch has conflicts, the panel shows "2 enrollment conflicts since the last reset. Auto-activation is paused until an admin resets enrollment." This also applies in state 3.1.

### 3.5 Revoked, offline, off
- **Revoked:** the verdict is red, "Access revoked", and the line reads "Marked compromised by anders.aslund@teknoir.ai 14 min ago: 'Unknown process on port 8443'." The comparison stays visible but greyed (opacity 0.5), because the identity itself is still the last known one.
- **Device offline:** the verdict keeps the last activation result. A yellow line reads "The device hasn't been connected to the hub since 15:02 (12 min ago). Values below are its last known state."
- **Off:** the whole content area is an empty state. The heading is "WireGuard access is off for this device", followed by:
  > Turn it on to reach SSH and the services you add here through an encrypted tunnel, without opening ports on the device.

  The button is **Turn on WireGuard** (admin). Non-admins see "Ask a teamspace admin to turn it on."

### 3.6 Accessibility of the comparison
- **Screen readers:**
  - The comparison is a `figure` with an `aria-label`, for example "Fingerprint comparison, 11 of 11 groups match".
  - The marks are `aria-hidden`.
  - A visually hidden list reads each group as "Group 4: eb+w, match".
- **Not colour alone:** match and mismatch use glyph and line style as well as colour. A match is a solid line, a mismatch is "≠" plus an underline on the differing characters, and pending is a dashed line.
- **Text:** the groups are selectable text. Copying the row copies the full `SHA256:` fingerprint without spaces, because the groups are visual only and the separators are CSS gaps.

## 4. Services

- **Panel:** the heading is **Services**, with a count. The right side has **Add service** (outlined, editors).
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
    - Waiting or mismatch: "Services open once the device identity is approved."
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
  - **Activation:** a segmented control, Automatic or Manual. Helper: "Automatic: a new device identity is activated when the device proves it holds the SSH host key Teknoir already knows. Manual: an admin approves every new identity."
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
| Clear flags | admins | none | "Restores WireGuard access if the identity is still approved. Sessions do not resume by themselves." |
| Reset enrollment | admins | none | "Forgets this device's WireGuard identity and anchors. The device enrolls again within a minute. With Automatic activation and a matching host key, it activates without you. Otherwise it waits for approval." |

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
| Approve identity, Update anchor, Reset enrollment, Clear flags, End session, WireGuard access, Direct connections, Activation mode, Web terminal, Turn on WireGuard | yes |
| Add or remove service, Mark compromised, Mark health check failed, Keep blocked | no (device editors) |
| Open, copy commands, read everything | no (device readers) |

The backend enforces all of these. The UI hides or disables controls only to avoid dead ends.

## 12. Backend needs this spec adds (for C0, W3, W4, W5)

1. **`…/ztna` response:**

   | Field | Purpose |
   |---|---|
   | `activation{mode, verifiedBy, anchorSource, anchorAt, attestedAt, hostKeyFingerprint, attestedHostKeyFingerprint}` | Identity panel. `attestedHostKeyFingerprint` is needed for the mismatch view |
   | `conflicts` | Enrollment conflicts this epoch |
   | `hub{connected, rttMs, lastHandshake, natClass}` | Connection panel |
   | `sessions[{id, user, service, client, path, since, rx, tx}]` | Live sessions table |
   | `services` (with `pending`) | Service cards and the Applying… tag |
   | `flags{compromised, healthFailed, by, at, reason}` | Trust panel |
   | `fetchedAt` | Live and stale indicator |

2. **`…/ztna/permissions`:** `{admin, editor}`.
3. **`DELETE …/ztna/sessions/:id`:** End session (admin).
4. **Device Services list:** the k3s Services for the picker (name, namespace, ports, appProtocol). The workloads data may already contain it. If not, it is a W4 item.
5. **Backend errors:** returned as `{message, field?}`, so the dialog can mark the field.

## 13. Self-critique log (prototype iterations)
Screenshots are in `/home/anders/git/ai/.playwright-mcp/ux-v1-*.png` (first pass) and `ux-v2-*.png` (after fixes), at 1440x900 and 768x1024. In the headless browser the prototype was served with `python3 -m http.server`, because the Playwright MCP blocks `file:` URLs.

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

**Kept on purpose**
- Full-width accent Open buttons, as on Tunneling.
- The supertitle with its middle dot, which is the shared shell.
- Two red-outlined flag buttons in the calm state, following the product's "destructive is red" rule.

## 14. Open questions for Anders

1. **Tab name and Tunneling:** should the tab be called "WireGuard" (proposed), or should it be merged with Tunneling into one "Access" tab later, once the legacy tunnels are retired? The service cards are deliberately built so Tunneling can become a filter of the same grid.
2. **Approving without pasting:** should an admin be able to approve without pasting the device's fingerprint, for example after comparing by phone? This draft requires the paste to match. A "Compare another way" escape is possible, but it weakens the check.
3. **Button case:** Tunneling's "OPEN TUNNEL" is uppercase, and WireGuard's buttons are sentence case. This draft uses sentence case. Should Tunneling be aligned when W5 touches it?
4. **Who may flag:** this draft lets device editors mark compromised and health failed, while clearing needs an admin. Is that the intended split?
5. **Overview and Devices list:** surface "Waiting for approval" and "Host key mismatch" as a chip there too (research U4 recommends it). Is that in scope for W5, or later?
6. **Path summary with no sessions:** the header predicts the path from the NAT class. Is a prediction acceptable there, or should it show a dash until a real session exists?
