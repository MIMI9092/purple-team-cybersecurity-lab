# Report Writing Handoff

> [!important] Purpose
> This is the durable continuation note for the internship report. Read it before
> drafting or revising any report section. It records the accepted structure,
> current writing state, technical facts, professor feedback, user preferences,
> unresolved decisions, and the exact next actions as of 11 September 2026.

## 1. Sources of Truth

Use these sources in this order:

1. The current Overleaf project is the source of truth for prose already written
   and the exact last completed subsection. The LaTeX project is not stored in
   this Obsidian vault.
2. This handoff is the source of truth for writing decisions, preferences, and
   continuation instructions.
3. [[Report Architecture and Presentation Strategy]] contains the detailed
   eleven-chapter architecture, figure and table inventories, identifier model,
   appendix boundary, and evidence strategy.
4. [[Report Outline]] is the compact chapter outline.
5. [[Project Progress]], [[Project Dashboard]], [[Attack Chain Overview]],
   [[Detection Coverage Matrix]], and [[Evidence Index]] are the technical-status
   sources.
6. Individual attack, detection, and playbook notes contain the evidence needed
   for the implementation chapters.

Do not infer a successful result from a planned design. Check the relevant
Obsidian evidence note and, where applicable, the saved replay evidence.

## 2. Current Report State

The report is being written in English in LaTeX on Overleaf. The folder structure
has been created and compilation works. The project uses the KOMA-Script
`scrreprt` class. The compiler setting should be verified in Overleaf before it
is changed. An earlier compile timeout did not prove that the compiler was the
cause, and the project subsequently compiled successfully.

The front matter and Chapter 1 have been drafted in Overleaf. Chapter 2 has also
been started. Based on the writing conversation, Chapter 2 contains at least the
purple-team model, the Cyber Kill Chain and MITRE ATT&CK discussion, their
combined use, network segmentation/controlled pivoting, and part of the
telemetry/detection foundation. Because the LaTeX files are not in this vault,
open Overleaf and confirm the last completed heading before generating the next
subsection.

The current Chapter 1 draft used a longer CBI structure. It must now be shortened
according to Section 9 of this handoff. Do not discard the complete draft until
the useful facts and citations have been preserved.

The title page compiled, but its final typography and spacing were deliberately
deferred because the user disliked the title font and size. It should be refined
after the main report has progressed further.

## 3. Institutional and Title-Page Information

Use the following confirmed information:

- Student: Mariam Ibni
- University: Université Sultan Moulay Slimane
- School: École Nationale des Sciences Appliquées de Khouribga
- Department/program wording supplied by the user: Cybersecurity and Intelligent
  Networks
- Host organization: CBI
- CBI supervisors: Yassine Medouar and Othmane Menouar
- Academic supervisor: Samir Achraf Chemkar
- Academic year shown in the supplied reference: 2025–2026
- Working report title: *Engineering a Segmented Purple-Team Laboratory with
  Cross-Source Detection and Analyst-Gated SOAR Response*

The three logos belong at the top of the title page. The requested order is the
university logo on the left, the smaller CBI logo in the center, and the ENSA
Khouribga logo on the right. The CBI logo must be visibly smaller than in the
first draft. Preserved assets are stored in:

- `09 - Report Material/Title Page Assets/logo-universite-sultan-moulay-slimane.png`
- `09 - Report Material/Title Page Assets/logo-cbi.jpg`
- `09 - Report Material/Title Page Assets/logo-ensa-khouribga.png`

The supplied reference title-page screenshot was temporary and was not preserved
successfully. Its relevant layout has been captured in this note: three logos,
institutional text, report type, project title, student and supervisors, internship
period, and academic year, all in a restrained academic layout.

The exact internship dates are not yet confirmed in this handoff. The reference
showed 1 July to 1 September 2026, but do not treat that as final until the user
confirms it. Do not leave “To be confirmed” in the final report.

CBI does not require a confidentiality statement.

## 4. Front-Matter Order and Known Issues

The accepted order is:

1. Title page
2. Institutional approval or declaration page, only if required
3. Acknowledgements
4. Summary or French `Résumé`, depending on the institutional convention
5. English Abstract
6. Keywords
7. Table of contents
8. List of figures
9. List of tables
10. List of listings
11. List of acronyms and symbols

Known items to fix near the report freeze:

- Confirm whether the school expects a French `Résumé` followed by an English
  Abstract. The current Summary and Abstract are both English and too similar.
- Replace all placeholder internship dates.
- Remove the List of Listings if it remains empty, unless the template requires it.
- Correct the acronym continuation-page running heading, which previously showed
  “List of Listings.”
- Finalize the title typography and spacing.
- Confirm any official margin, font, page-limit, and submission requirements.

Do not spend more time polishing the front page now unless it blocks compilation.

## 5. LaTeX and File Conventions

- Keep chapter filenames in the numeric format already created, for example
  `chapters/01-introduction.tex`, `chapters/02-foundations.tex`, and
  `chapters/03-requirements-methodology.tex`.
- Do not rename them to forms such as `chapter01-introduction.tex`.
- Keep `main.tex` as the root document.
- Preserve the existing folder structure under `config`, `frontmatter`,
  `chapters`, `appendices`, `figures`, `tables`, `code`, and `bibliography`.
- Use `references.bib` as the single bibliography database.
- Prefer `listings` over `minted` to avoid shell-escape dependencies.
- Use KOMA-native page and heading controls. Do not mix `scrreprt` with
  `titlesec` or `fancyhdr` unless there is a demonstrated necessity.
- An earlier blank-page problem was resolved. If it returns, check duplicate page
  breaks, title-page termination, and KOMA open-right behavior before changing
  the document class.
- When giving the user a replacement, state the exact file and exact block to
  replace. Provide a full file only when the user explicitly requests it.

## 6. Non-Negotiable Writing Preferences

These preferences apply to every future section:

- Write natural, polished academic English that sounds like a student explaining
  work they genuinely performed. Avoid robotic, generic, or promotional prose.
- Do not insert the student's name into ordinary project-context prose.
- Do not repeatedly say “this project,” “this report,” “controlled environment,”
  or restate the complete attack-to-response pipeline in every subsection.
- Never use em dashes or the `---` construction in report prose. Use commas,
  parentheses, colons, or separate sentences.
- Avoid exaggerated claims. Prefer “controlled adversary-emulation scenario,”
  “representative multi-stage intrusion scenario,” or “realistic attack
  progression in a controlled laboratory.” Do not call it equivalent to a
  real-world adversarial engagement.
- Explanations should lead with the engineering purpose and result, then provide
  only the theory needed to understand the design.
- Avoid textbook-style question-and-answer fragments such as “The Cyber Kill
  Chain answers the question...” followed by a standalone question. Integrate
  the comparison naturally into a paragraph.
- Do not write the offensive chapter as a command tutorial. Explain the
  trust-boundary, identity, telemetry, and control transitions.
- Do not paste large raw commands, complete SPL searches, long configuration
  dumps, or every Shuffle node into the main body. Put full technical material
  in appendices.
- Do not use unnumbered source captions such as
  `\caption*{Author's synthesis based on...}`.
- Always place `\caption{...}` after the figure, diagram, or table content, never
  before it.
- Keep captions concise and focused on what the item demonstrates.
- Every figure, table, and listing must be introduced or interpreted in prose.
- Preserve the restrained academic visual style. Avoid decorative diagrams.
- When the user says “next,” continue with the next agreed subsection without
  repeating the plan or rewriting accepted sections.
- Work section by section. The user prefers paste-ready LaTeX in manageable
  blocks rather than an enormous chapter dump.

## 7. Central Report Argument

The report must make the following chain explicit without repeating it
mechanically:

1. A controlled adversary behavior was executed.
2. The attack-side evidence established ground truth.
3. The relevant source systems did or did not record expected telemetry.
4. Splunk did or did not ingest that telemetry.
5. An atomic detection did or did not identify the behavior.
6. Cross-source correlation did or did not reconstruct the broader campaign.
7. Shuffle did or did not select and execute the expected response route.
8. Independent checks did or did not verify containment and recovery.

The report must never treat these as the same success condition. Use the status
vocabulary `VERIFIED`, `NOT OBSERVED`, `INCONCLUSIVE`, and `FAILED`. A local attack
proof may be `VERIFIED` while its central Splunk detection remains incomplete.

The core contribution is not merely connecting tools. It is the engineering of
a segmented, evidence-driven validation loop with explicit trust boundaries,
cross-source correlation, analyst authorization, fail-closed behavior, scoped
containment, independent verification, and preserved evidence.

## 8. Accepted Eleven-Chapter Structure

### Chapter 1: Introduction and Project Framing

Use a concise target structure:

1. Internship Framework and Project Context
2. Host Organization: CBI
   1. General Presentation
   2. Cybersecurity and SOC Activity
   3. Relevance to the Internship
3. Problem Statement
4. Objectives
5. Scope, Exclusions, and Safety Boundaries
6. Main Contributions
7. Project Phases and Time Allocation

The user explicitly preferred a phase/time-allocation section over a generic
“Report Structure” subsection. The project planning figure should show how the
internship effort was distributed across phases, not merely list the chapters.

### Chapter 2: Technical Foundations and Design Rationale

Keep this chapter concise:

1. Purple-Team Security Model
2. Attack-Lifecycle Models
   1. Cyber Kill Chain
   2. MITRE ATT&CK
   3. Complementary Use in the Project
3. Network Segmentation and Controlled Pivoting
4. Telemetry, Detection, SIEM, and SOAR Foundations
5. Related Work and Project Positioning
6. Technology Stack and Selection Rationale

Move detailed validation methodology to Chapter 3. Do not add separate tutorials
for reverse shells, Chisel, WinRM, Kerberoasting, service weaknesses, Run keys,
Splunk, or Shuffle here.

### Chapter 3: Requirements, Threat Model and Engineering Methodology

Include:

1. Stakeholders and operational viewpoint
2. Functional requirements
3. Security and non-functional requirements
4. Measurable host and virtualization constraints
5. Assets and trust boundaries
6. Threat model and attacker assumptions
7. Safety controls and authorization model
8. Iterative build, simulate, observe, detect, correlate, respond, verify method
9. Ground-truth and defensive-observation model
10. Evidence, acceptance-status, and reproducibility method

### Chapter 4: Laboratory Architecture and Implementation

Cover VMware, GNS3, the complete VM inventory, OPNsense, routing, VLANs, NAT,
firewall policy, DVWA, Windows 10, Active Directory, Kali, Splunk, Universal
Forwarders, Suricata, Shuffle, data flows, addressing, trust boundaries, and
operational constraints. GNS3 must not be omitted.

### Chapter 5: Controlled Offensive Scenario and Purple-Team Simulation

Present the representative multi-stage scenario, the DMZ compromise, pivot,
WinRM access, AD discovery, local service-file privilege escalation,
Kerberoasting, offline password validation, valid-account use, authorization
testing, persistence, C2, and the replay automation. Present password spraying
as a supplemental validation rather than forcing it into the linear chain.

### Chapter 6: Telemetry and Atomic Detection Engineering

Derive source and field requirements from attacker behaviors, explain onboarding
and normalization, distinguish event time from index time, document the atomic
detection method, highlight representative detections, and summarize gaps.

### Chapter 7: Cross-Source Correlation and SIEM Engineering

Explain entity resolution, time windows, confidence, campaign semantics, D08,
D13, D15, D18, the executive dashboard, scheduler reliability, and the pending
privilege-escalation correlation. Keep license recovery and troubleshooting
concise.

### Chapter 8: SOAR Orchestration and Response Engineering

Present PB02 through PB05 as cumulative engineering evolution. PB01 is an early
lesson, not an equal mature result. Emphasize decision engineering, analyst
approval, scoped actions, verification, audit, failure handling, and recovery.

### Chapter 9: Testing and Validation

Document test cases, acceptance criteria, attack validation, telemetry checks,
atomic detection, correlation, playbook routes, negative tests, fail-closed
tests, containment verification, scheduler behavior, reproducibility, and a
consolidated status matrix.

### Chapter 10: Results, Discussion and Limitations

Answer the objectives, present end-to-end traceability, analyze engineering
findings and trade-offs, distinguish completed from partial results, and discuss
limitations without presenting them as apologies.

### Chapter 11: Conclusion and Future Work

Summarize the engineering contribution and prioritize genuinely deferred work,
including optional ticketing, stronger endpoint telemetry, further correlation,
and safe operational improvements.

## 9. Professor Review and Adopted Decisions

All fifteen remarks were evaluated. Apply them as follows.

### 9.1 Rebalance the report

Accepted. Chapters 1 and 2 must not continue expanding. Practical engineering,
testing, results, and critical analysis should occupy roughly 70 percent of the
main body. Page number alone can be misleading because front matter contributes
pages, but the main-body balance must clearly favor Chapters 4 through 10.

### 9.2 Shorten the CBI presentation

Accepted. Keep the general presentation, cybersecurity/SOC activity, and direct
relevance. Merge useful key figures or expertise into compact prose. Reduce
geographical presence to one sentence. Remove the standalone vendor-ecosystem
discussion unless one specific partnership directly explains a project choice.

### 9.3 Define “resource-constrained laboratory” precisely

Accepted, but do not invent specifications. Chapter 3 must record actual host
CPU, RAM, storage, VMware/GNS3 limits, VM allocations, number of VMs and services,
which components could run simultaneously, and the resulting compromises. Until
those values are collected, prefer “isolated virtual laboratory operating within
fixed host resources” over an unsupported quantitative claim.

### 9.4 Add short related work

Accepted. Add only a concise subsection and comparison covering offensive labs,
detection/SIEM labs, SOC/SOAR labs, and the integrated approach used here. Support
the comparison with appropriate academic or authoritative references. Do not
turn Chapter 2 into a large literature review.

### 9.5 Correct the Cyber Kill Chain mapping

Accepted. Use Kill Chain only for the high-level narrative and do not force all
seven stages. The corrected interpretation appears in Section 10.

### 9.6 Correct the privilege-escalation ATT&CK mapping

Accepted after code-level verification. The definitive mapping appears in
Section 11.

### 9.7 Add a threat model before implementation

Accepted. Chapter 3 must state starting position, attacker knowledge, credentials
available by stage, trust boundaries, intentional vulnerabilities, prohibited
shortcuts, valid routes, and explicit success/failure criteria. Direct
controller-to-Windows connectivity never validates the offensive pivot.

### 9.8 Elevate ground truth versus defensive observation

Accepted as a central contribution. Build one master traceability matrix and use
filtered views in later chapters. Do not create independent, inconsistent tables.

### 9.9 Treat SOAR as decision engineering

Accepted. For each important playbook explain trigger, normalization, campaign
identity, enrichment, timeline, authorization, decision logic, risk/outcome,
containment profile, analyst approval, action, verification, recovery, audit,
and failure handling. Use diagrams and decision tables, not a screenshot tour.

### 9.10 Treat Splunk as detection engineering

Accepted. For representative detections document hypothesis, attacker behavior,
data source, fields, SPL logic, expected evidence, false positives, test method,
observed result, and correlation role. Keep full SPL in Appendix C.

### 9.11 Use careful realism terminology

Accepted. Use the controlled/representative terminology in Section 6.

### 9.12 Remove repetition

Accepted. Chapter 1 states the promise, Chapter 2 provides only the foundation,
and later chapters demonstrate the work. Delete paragraphs that merely repeat
the project slogan without adding a design decision, result, or limitation.

### 9.13 Strengthen and standardize references

Accepted. Use one numeric/IEEE-style bibliography consistently, including CBI
sources where practical. Prefer primary standards, official documentation, and
original research. Add references for detection engineering, SIEM, SOAR,
analyst approval, incident response, and reproducibility where used.

### 9.14 Fix front matter later

Accepted and deliberately deferred. Use the checklist in Section 4 near the
report freeze.

### 9.15 Preserve the visual style

Accepted. Keep the current restrained style and prioritize technical figures:
topology and trust boundaries, attack path, telemetry architecture, detection
pipeline, correlation sequence, SOAR architecture, decision flow, and the
end-to-end traceability model.

## 10. Correct Cyber Kill Chain Use

Use this interpretation when revising the current Chapter 2 table:

- Reconnaissance is represented by limited, authorized discovery and enumeration.
- Weaponization is not represented as an observed adversary stage. Preparing
  replay scripts and tools is laboratory engineering, not realistic attacker
  weaponization evidence.
- Delivery is not distinctly represented. DVWA interaction transitions directly
  into exploitation rather than demonstrating a separate delivery mechanism.
- Exploitation is represented by controlled exploitation of intentionally
  vulnerable DVWA functionality.
- Installation is represented only where controlled persistence artifacts are
  established after access.
- Command and Control is represented by the Chisel callback and reverse tunnelling
  channels.
- Actions on Objectives is not represented as a separate business-impact stage.
  The replay stops at defined technical boundaries and performs no collection,
  exfiltration, destruction, or operational-impact action.

Do not force pivoting, WinRM, credential access, and privilege escalation into
“Actions on Objectives.” Use MITRE ATT&CK for those precise behaviors.

## 11. Definitive Privilege-Escalation Mapping

The code was inspected on 11 September 2026. The attack behavior is:

1. An administrator installs a lab-only `PFA-Lab-Updater` service under
   `LocalSystem` as a fixture.
2. Its protected wrapper launches
   `C:\ProgramData\PFA-Lab\PrivilegeEscalation\PFA-Lab-Updater.ps1` through
   Windows PowerShell.
3. The fixture grants `LAB\svc_web` Modify permission on only that script and
   limited service rights including START.
4. During the attack replay, `LAB\svc_web` overwrites the script with the
   hash-verified proof payload.
5. `LAB\svc_web` starts the existing service without creating, reconfiguring, or
   replacing the service executable.
6. The service launches the modified PowerShell script as
   `NT AUTHORITY\SYSTEM`, which writes structured proof.

Use these mappings:

- Primary mechanism: `T1574.010`, Hijack Execution Flow: Services File
  Permissions Weakness.
- Secondary execution behavior: `T1569.002`, System Services: Service Execution.
- Secondary interpreter behavior: `T1059.001`, PowerShell.
- `T1543.003`, Create or Modify System Process: Windows Service, describes fixture
  provisioning by the administrator. It is not an attacker-phase mapping because
  `svc_web` does not create or reconfigure the service.
- Do not use `T1068`; no kernel or software exploit is involved.

The detection story should preserve both identities and the causal order:

`LAB\svc_web` writes the vulnerable service script, the service is started, the
LocalSystem wrapper launches PowerShell, and the SYSTEM proof artifact is
generated.

Expected telemetry includes Security `4663`, Security `4688`, PowerShell `4104`,
System `7036`, and Application `9101`.

Primary notes and evidence:

- [[05A - Local Privilege Escalation]]
- Replay run `PTR-20260909T162419Z-355a0dc0`
- Evidence folder
  `10 - Automation/Purple-Team-Attack-Replay/evidence/PTR-20260909T162419Z-355a0dc0`

The local identity transition is `VERIFIED`. Splunk collection and correlation
of the preserved Windows events remain pending and must not be reported as
completed detection coverage.

## 12. Threat-Model Facts to Preserve

- The work is performed only in an authorized, isolated virtual laboratory.
- Kali represents the external attacker/controller position.
- DVWA is the intentionally vulnerable public-facing application in the DMZ.
- The valid offensive path crosses the documented OPNsense/GNS3 boundaries,
  compromises the DMZ application, creates the approved pivot, and reaches
  Windows through that pivot.
- Direct controller-to-Windows connectivity is not accepted as pivot evidence.
- Credentials are introduced or obtained only at documented stages. Never imply
  that the attacker possessed later-stage credentials from the start.
- The `PFA-Lab-Updater` service weakness is a deterministic lab fixture, not a
  discovered production vulnerability.
- Attack-only replay keeps Splunk and Shuffle off where required so attack-side
  ground truth is established independently. Preserved endpoint/network events
  are ingested later for defensive validation.
- The replay fails closed on unexpected identity, hash, service path, state,
  address, stale proof, or prerequisite mismatch.
- No real target, production customer system, uncontrolled account lockout,
  destructive payload, exfiltration, or business-impact action is authorized.

## 13. Current Technical Status Relevant to the Report

Completed and evidenced:

- Segmented VMware/GNS3 laboratory and OPNsense routing/firewalling
- Kali, DVWA, Windows 10, Active Directory, Splunk, Suricata, and Shuffle
- External reconnaissance and DVWA exploitation
- DMZ reverse shell and Chisel pivot
- WinRM access and AD discovery
- Kerberoasting, offline credential validation, valid-account use, and
  authorization-boundary testing
- Controlled `LAB\svc_web` to `NT AUTHORITY\SYSTEM` service-file scenario
- HKCU Run-key persistence and Windows reverse SOCKS/C2 simulation
- Phase 1, Phase 2, and Phase 3 atomic/correlation detections
- D08, D13, D15, and D18 cross-source correlation cases
- OPS01 telemetry-health detection
- PB02, PB03, PB04, and PB05 response engineering and validation
- Enterprise Developer Splunk license, 10 GB/day, expiring 6 March 2027
- Twelve-panel Purple Team Executive Overview dashboard

Dashboard validation with `All time` selected showed 799,276 security events,
10 active data sources, 25 enabled detections, and 2,692 detection hits. Earlier
zero values under `Last 24 hours` reflected stopped data sources and the selected
time range, not a broken license or dashboard.

The controlled password-spray test is supplemental. The initial missing Event
`4771` failure telemetry was a real source-auditing gap. Success and Failure
Kerberos auditing was later enabled, two controlled failures reached Splunk, and
the D03 manual search returned both. Only the current D03 scheduled-alert state
and a current trigger or scheduler-history record require final auditing. See
[[11 - Controlled Password Spraying]].

PB01 is historical experimentation. PB02 is the first mature response model,
PB03 demonstrates web/network response, PB04 demonstrates identity-response
controls, and PB05 is the most mature layered endpoint/network response.

Optional ticketing and additional Shuffle refinements are not required for the
first report baseline. If added later and validated, revise the report. Otherwise
present them as future work.

## 14. High-Priority Missing Evidence and Operational Tasks

Complete or explicitly classify these before the final report freeze:

1. Start the appropriate monitoring path and validate the preserved privilege-
   escalation events in Splunk before resetting the Windows fixture.
2. Confirm Universal Forwarder collection of Security, PowerShell Operational,
   System, and Application channels.
3. Correlate the `4663`, `4688`, `4104`, `7036`, and `9101` sequence and assign
   the final detection/correlation status.
4. Re-audit D03's current saved-search state and preserve a scheduled trigger or
   scheduler-history result.
5. Export the final Splunk saved-search catalog, schedules, severity, sharing,
   and enabled/disabled state.
6. Export accepted Shuffle workflows, lookup data, and the restricted PB05 app
   in sanitized form.
7. Curate the screenshot set and index the final evidence IDs.
8. Confirm the final safe state: `svc_sql` enabled, temporary firewall aliases
   empty, and lab artifacts reset only after evidence collection.
9. Rotate the Brevo credential that was exposed during troubleshooting.
10. Collect exact host and VM resource specifications for Chapter 3.

Do not calculate MTTD, MTTR, false-positive percentages, or risk-reduction
percentages unless the underlying timestamps and sample sizes support them.

## 15. Screenshot and Figure Rules

The named screenshot source is:

`C:\Users\DELL\Images\projects`

It contains approximately 94 candidate PNG files. Do not use all of them.

Use screenshots only when they prove a decisive claim, such as:

- a representative Splunk correlation result;
- the SYSTEM identity proof and causal evidence;
- an analyst approval decision;
- verified containment;
- a fail-closed outcome;
- the clean executive dashboard.

Prefer diagrams and tables for architecture, pipelines, mappings, and decision
logic. Export diagrams as vector PDF. Use cropped PNG for UI evidence. Avoid JPEG
for text-heavy screenshots. Redact passwords, hashes that expose credentials,
cookies, API keys, approval URLs, license identifiers, Kerberos caches, and
unnecessary personal data.

Essential figure plan:

- F01 segmented laboratory and trust boundaries
- F02 SOC evidence and response data flow
- F03 iterative purple-team methodology
- F04 internship phase/time-allocation chart
- F05 controlled offensive scenario
- F06 local privilege-escalation causal chain
- F07 detection-engineering pipeline
- F08 D13 cross-source correlation sequence
- F09 shared SOAR reference architecture
- F10 analyst-gated response lifecycle
- F11 PB02-to-PB03 response evolution
- F12 PB04 identity-response workflow
- F13 PB05 layered endpoint/C2 workflow

Use consistent canonical IDs and labels. Do not invent new aliases for existing
objects such as D08, D13, D15, D18, OPS01, PB04, or PB05.

## 16. Documentation Models for Later Chapters

For each attack phase, present:

1. Objective
2. Preconditions and authorized route
3. Controlled procedure at a conceptual level
4. Result and identity/trust-boundary transition
5. Ground-truth evidence
6. Expected and observed telemetry
7. Detection/correlation reference
8. Gap or limitation
9. Defensive improvement

For each representative Splunk detection, present:

1. Detection objective and hypothesis
2. Attacker behavior
3. Data source and required fields
4. SPL logic in summarized form
5. Expected evidence
6. False-positive considerations
7. Test procedure
8. Observed result
9. Role in higher-level correlation
10. Validation status and evidence ID

For each important Shuffle playbook, present:

1. Triggering detection
2. Normalization contract
3. Case or campaign identity
4. Enrichment and timeline reconstruction
5. Authorization checks
6. Decision logic and risk/outcome classification
7. Containment profile selection
8. Analyst approval
9. Scoped action
10. Independent verification
11. Audit and notification
12. Recovery or rollback policy
13. Failure handling and fail-closed behavior

## 17. References Strategy

- Use a single numeric/IEEE-style citation system unless the official school
  template requires another style.
- Gradually migrate CBI web references from ad hoc footnotes into the shared
  bibliography for consistency.
- Prefer MITRE ATT&CK, NIST, Microsoft, CISA, Splunk, Suricata, OPNsense, Shuffle,
  GNS3, VMware, and original research where they directly support a claim.
- Do not cite a source merely because it mentions a tool. Cite it where it
  supports a definition, design choice, event interpretation, or limitation.
- Related-work claims require actual references.
- Do not overload implementation paragraphs with citations for facts directly
  demonstrated by project evidence. Cite the external technical definition and
  separately identify the project evidence.

## 18. Exact Next Writing Sequence

At the start of the next report-writing conversation:

1. Open Overleaf and identify the exact last completed Chapter 2 heading.
2. Before adding more theory, revise the existing Cyber Kill Chain table using
   Section 10 of this handoff.
3. Replace the privilege-escalation ATT&CK row with the mapping in Section 11.
4. Shorten the Chapter 1 CBI material without losing useful facts or citations.
5. Finish only the remaining concise Chapter 2 material, including a short
   related-work comparison and a compact technology-stack rationale.
6. Begin Chapter 3 with measurable requirements, the threat model, explicit
   route restrictions, resource constraints, and the ground-truth versus
   defensive-observation model.

Do not continue expanding general theory before these corrections are made.

## 19. Facts Still Requiring User Confirmation

Ask only when the answer becomes necessary:

- Exact internship start and end dates
- Official school requirements for margins, font, maximum pages, and submission
- French `Résumé` plus English Abstract versus two English front-matter summaries
- Exact host hardware and final per-VM allocations
- Final title approval
- Exact last completed Overleaf subsection

Do not repeatedly ask about already confirmed names, organization, chapter
structure, caption placement, file naming, or writing style.

## 20. Examiner-Facing Quality Test

Every major chapter should help an examiner answer at least one of these:

- What did the student actually build?
- How was it tested?
- What evidence proves it worked?
- What did not work or remains partial?
- Why were these design choices made?
- What are the technical and methodological limitations?
- What is the engineering contribution beyond connecting existing tools?

If a paragraph does not support one of those questions, provide necessary
context, or connect two technical decisions, it is a candidate for deletion or
compression.

## 21. Compact Continuation Prompt

If a new conversation lacks context, provide this instruction:

> Read `09 - Report Material/Report Writing Handoff.md`, then read the report
> architecture and the relevant technical evidence note for the section being
> drafted. Continue from the exact last heading in Overleaf. Follow all writing,
> caption, filename, evidence-status, and terminology rules in the handoff. Do
> not rewrite accepted material unless a recorded correction requires it.
