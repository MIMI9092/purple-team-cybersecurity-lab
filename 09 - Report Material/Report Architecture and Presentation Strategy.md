# Report Architecture and Presentation Strategy

## Planning Status

This note defines the architecture of the final English-language internship
report. It is a planning artifact, not report prose. Writing is now underway in
LaTeX on Overleaf. Read [[Report Writing Handoff]] first for the latest writing
status, professor-review decisions, user preferences, and continuation order.

### Revision Status — 10 September 2026

The eleven-chapter backbone and central engineering narrative are retained.
This revision deliberately simplifies Chapter 2, reframes Chapter 5 around the
controlled offensive scenario, makes Chapter 7 correlation-led, turns Chapter
8 into a PB02-to-PB05 engineering-evolution story, reduces the figure set,
simplifies the Gantt chart and establishes stable cross-artifact identifiers.
The architecture is revised but not yet frozen; no report prose or `main.tex`
has been created.

Recommended working title:

> **Engineering a Segmented Purple-Team Laboratory with Cross-Source Detection
> and Analyst-Gated SOAR Response**

This title is more specific than *Offensive and Defensive Cybersecurity Lab*.
It highlights the engineering contributions: segmentation, reproducible attack
simulation, multi-source detection and controlled response.

The practical engineering chapters should occupy roughly 70% of the main body.
The background chapter should remain near 10% and introduce only concepts used
later in the design or evaluation.

## A. Final Recommended Table of Contents

### Front Matter

- Title page
- Institutional approval/declaration page, only if required
- Acknowledgements
- Summary
- Abstract
- Keywords
- Table of contents
- List of figures
- List of tables
- List of listings
- List of acronyms and symbols

The front-page layout and logo placement will follow the reference supplied by
Mariam. CBI does not require a confidentiality statement. Both a Summary and an
Abstract are currently planned because the required front-matter sequence was
confirmed; keep them complementary rather than duplicating the same paragraph.
Unless the institutional template says otherwise, both remain in English to
respect the report-language decision.

### Chapter 1 — Introduction and Project Framing

1. Context and motivation
2. Host organization: CBI
   1. Company presentation and core activities
   2. Relevant organizational and technical context
3. Internship framework (`Cadre de stage`)
   1. Host team and supervision
   2. Assigned mission
   3. Organizational and technical scope
4. Problem statement
5. Project objectives
6. Engineering questions and success criteria
7. Scope and exclusions
8. Ethical, legal and laboratory-safety boundaries
9. Main contributions
10. Report organization

Keep the CBI presentation factual and short. It should establish why the
internship setting is relevant to the project, then transition directly into
the assigned cybersecurity engineering mission. Avoid turning it into a long
corporate brochure.

### Chapter 2 — Technical Foundations and Design Rationale

1. Purple-team engineering as an iterative validation process
2. Attack modeling
   1. MITRE ATT&CK as the technique vocabulary
   2. Cyber Kill Chain as a high-level narrative model
3. Telemetry and detection engineering
   1. Evidence requirements and data quality
   2. Atomic detection and cross-source correlation
4. SIEM, campaign detection and alert semantics
5. SOAR and controlled incident response
   1. NIST incident-response lifecycle
   2. Analyst-gated, fail-closed and reversible automation
6. Compact threat-technique families used by the scenario
   1. Public-facing access and code execution
   2. Pivoting and lateral movement
   3. Identity and credential access
   4. Privilege escalation, persistence and command-and-control
7. Design implications for this project

Chapter 2 introduces technique families only far enough to explain the threat
model and defensive requirements. It must not contain separate tutorials on
reverse shells, Chisel, WinRM, Kerberoasting, writable service scripts, Run
keys or reverse SOCKS. Those details appear once, at their point of use in
Chapter 5, alongside their exact trust-boundary, telemetry and validation
context.

### Chapter 3 — Requirements, Threat Model and Engineering Methodology

1. Stakeholders and operational viewpoint
2. Functional requirements
3. Security and non-functional requirements
4. Assets, trust boundaries and assumed attacker capabilities
5. Scope constraints and threat model
6. Safety controls and authorization model
7. Iterative engineering methodology
   1. Build
   2. Simulate
   3. Observe
   4. Detect
   5. Orchestrate
   6. Validate and improve
8. Validation and evidence methodology
9. Internship project schedule and milestones

### Chapter 4 — Laboratory Architecture and Implementation

1. Architecture overview
2. Virtualization and network-emulation platforms
3. Asset inventory and addressing plan
4. Security zones and trust boundaries
   1. External zone
   2. DMZ
   3. Transit network
   4. Internal/Active Directory VLAN
   5. SOC VLAN
5. Routing, VLANs, NAT and firewall policy
6. Windows and Active Directory environment
7. SOC and monitoring architecture
   1. OPNsense and Suricata
   2. Splunk Enterprise and Universal Forwarders
   3. Shuffle SOAR
8. Telemetry transport, indexes and management interfaces
9. Architecture validation and operational constraints

### Chapter 5 — Controlled Offensive Scenario and Purple-Team Simulation

1. Scenario objective, initial conditions and safety scope
2. Scenario design, trust-boundary path and ATT&CK mapping
3. Scenario execution: initial access and DMZ compromise
   1. External reconnaissance
   2. DVWA SQL injection and enumeration
   3. Command injection and reverse shell
4. Scenario execution: internal pivot and lateral access
   1. Chisel DMZ tunnel
   2. Internal service discovery
   3. WinRM access as `LAB\svc_web`
5. Scenario execution: discovery and local privilege escalation
   1. Windows and Active Directory discovery
   2. Writable service-script condition
   3. `LAB\svc_web` to `NT AUTHORITY\SYSTEM` proof
6. Scenario execution: credential access and valid-account use
   1. Kerberoasting of `svc_sql`
   2. Offline credential validation
   3. Authorization-boundary testing
7. Scenario execution: persistence and command and control
   1. HKCU Run-key persistence
   2. Windows reverse SOCKS callback
8. Supplemental controlled password-spray test
9. Replay automation as an engineering contribution
   1. Scenario model and controller
   2. Preconditions and fail-closed checks
   3. Credential handling
   4. Evidence and attack-boundary controls
   5. Cleanup model
10. Scenario outcome and transition to defensive observation

The password-spray test is presented as a supplemental validation, not forced
into the linear core chain. The initial Event `4771` visibility gap was later
remediated: Success and Failure auditing was enabled, two controlled failures
reached Splunk, and the D03 manual detection search returned both. The report
must distinguish this completed telemetry/search validation from the remaining
need to re-audit D03's current scheduled state and preserve trigger evidence.

### Chapter 6 — Telemetry and Atomic Detection Engineering

1. Telemetry requirements derived from the attack chain
2. Data-source onboarding and field model
   1. OPNsense filter logs
   2. Suricata EVE and alert data
   3. DVWA/Docker and Linux logs
   4. Windows Security and PowerShell logs
   5. Splunk internal scheduler and ingestion data
3. Time synchronization, event time and index time
4. Atomic detection design method
   1. Detection purpose and hypothesis
   2. Data requirements
   3. SPL logic and thresholds
   4. Severity and confidence
   5. False-positive analysis
   6. Validation evidence
5. Representative atomic detections by attack phase
6. Detection tuning and field-normalization lessons
7. Telemetry-health detection with OPS01
8. Atomic coverage summary and remaining gaps

### Chapter 7 — Cross-Source Correlation and SIEM Engineering

1. Why isolated alerts are insufficient
2. Correlation model: entities, stages and time windows
3. Cross-source evidence normalization
   1. Entity resolution across IP addresses, hosts, users and services
   2. Event-time, index-time and correlation windows
4. Representative correlation engineering
   1. Web-to-network correlation: D08
   2. Full compromise-to-internal-access correlation: D13
   3. Credential-access-to-valid-use correlation: D15
   4. Endpoint-to-network persistence/C2 correlation: D18
5. Campaign identification, confidence and alert semantics
6. Correlation validation and resulting SIEM capabilities
7. Purple Team Executive Overview dashboard
8. Pending service privilege-escalation correlation
9. Operational reliability, constraints and engineering challenges
   1. Search scheduling, runtime and skipped-search control
   2. License restoration and data availability
   3. Operational lessons and residual constraints

Only the logic of representative searches belongs in the main body. Complete
SPL is placed in the detection appendix. Operational recovery is supporting
evidence, not a primary contribution: keep it concise here, put measured
scheduler results in Chapter 9 and interpret broader constraints in Chapter 10.

### Chapter 8 — SOAR Orchestration and Response Engineering

1. Engineering question and evolution from PB02 to PB05
2. Shared Splunk-to-Shuffle reference architecture and data contracts
3. Shared response lifecycle
   1. Trigger and normalization
   2. Enrichment and timeline reconstruction
   3. Risk/outcome classification
   4. Analyst approval
   5. Scoped containment
   6. Independent verification
   7. Audit, notification and recovery
4. Shared controls and reusable components
   1. Authorization and asset lookups
   2. Versioned cases and immutable pre-action evidence
   3. NTF01, FW01 and FW02 helpers
5. PB02 — foundational reconnaissance-response model
   1. Detection intake, enrichment and assessment
   2. Scoped source containment and verification
   3. First reusable architectural principles
   4. Validated scope and deferred rollback policy
6. PB03 — correlated web-exploitation response
   1. Web/network correlation and evidence enrichment
   2. Outcome classification and containment profiles
   3. Analyst approval and scoped OPNsense response
   4. CP2/CP3 verification, audit and lessons carried forward
   5. Engineering advances beyond PB02
7. PB04 — risk-controlled identity response
   1. D14/D15 intake and enrichment
   2. I1–I4 assessment and IRP0–IRP4 routing
   3. IRP2 monitoring validation
   4. IRP3 analyst-approved temporary disable
   5. Stronger authorization, fail-closed checks and manual recovery
   6. Engineering advances beyond PB03
8. PB05 — mature persistence and C2 response
   1. D17/D18 intake and campaign correlation
   2. P1–P4 assessment and CRP0–CRP4 routing
   3. Endpoint and OPNsense containment
   4. Native analyst approval and layered verification
   5. Restricted endpoint actions, reusable helpers and evidence preservation
   6. Engineering advances beyond PB04
9. PB02-to-PB05 evolution synthesis
   1. Capability-evolution matrix
   2. Reused patterns and increasing control maturity
   3. Separation of investigation, authorization and state-changing action
10. Cross-playbook fail-closed, rollback and recovery analysis
11. PB01 as an early iteration and lesson learned
12. Deferred ticketing and workflow refinements

PB02 is the first mature response model in the report, PB03 is a substantive
end-to-end web/network case, PB04 demonstrates stronger identity-action
controls, and PB05 represents the most mature layered endpoint/network design.
The progression must be presented as cumulative learning, not a ranking in
which the earlier playbooks are described as failures. PB01 remains a short
pre-PB02 lesson showing why rollback independence and branch verification
matter.

### Chapter 9 — Testing and Validation

1. Validation objectives and test environment
2. Test-case structure and acceptance criteria
3. Attack and replay validation
4. Atomic detection validation
5. Correlation validation
6. SOAR route and response validation
7. Negative and fail-closed testing
8. Containment and recovery verification
9. Scheduler and telemetry-health validation
10. Metrics and KPI results
11. Reproducibility and threats to validity
12. Consolidated pass/partial/deferred matrix

### Chapter 10 — Results, Discussion and Limitations

1. Results against the original objectives
2. End-to-end offensive-to-defensive traceability
3. Principal engineering findings
4. Security-control trade-offs
5. Detection and response limitations
6. Operational and laboratory constraints
7. Generalizability and threats to validity
8. Lessons learned

### Chapter 11 — Conclusion and Future Work

1. Summary of the engineering contribution
2. Final answer to the project questions
3. Prioritized future work
   1. Validate the service privilege-escalation correlation in Splunk
   2. Re-audit D03's current scheduled state and preserve trigger evidence
   3. Add optional ticketing/case-platform integration
   4. Improve PB01 rollback independence if PB01 is resumed
   5. Evaluate Sysmon and stronger endpoint telemetry
   6. Replace lab service-account practices with production-grade controls

### Back Matter

- Bibliography
- Appendices
  - Appendix A — Detailed architecture, assets and network policy
  - Appendix B — Attack-stage and ATT&CK catalog
  - Appendix C — Detection catalog and complete SPL
  - Appendix D — Telemetry schemas and field mappings
  - Appendix E — SOAR data contracts, response profiles and workflow details
  - Appendix F — Validation matrix, metrics and evidence catalog
  - Appendix G — Selected configuration and automation listings

## B. Chapter-by-Chapter Explanation

| Chapter | Purpose and project content | Connection | Avoid or move elsewhere |
|---|---|---|---|
| 1. Introduction | Present CBI and the internship framework briefly, then frame the segmentation, visibility and safe-response problem; state measurable objectives, scope and contributions. | Connects the host context and assigned mission to the questions answered by Chapters 4–10. | Avoid corporate-brochure language, product descriptions, command output and result claims without evidence. |
| 2. Foundations | Introduce the purple-team method, ATT&CK, Kill Chain, telemetry, detection, correlation, SIEM, SOAR, NIST IR and controlled automation, followed by one compact threat-technique-family overview. | Converts the problem into design principles used in Chapter 3 without pre-explaining Chapter 5. | Avoid tool-specific or technique-by-technique tutorials, vendor histories and repeated attack detail. |
| 3. Requirements and Methodology | Define functional/security requirements, threat model, safety constraints, iterative method, acceptance criteria and Gantt. | Explains why the architecture and tests have their form. | Avoid repeating implementation details or reporting results prematurely. |
| 4. Architecture and Implementation | Present VMware/GNS3 deployment, OPNsense zones, addressing, routing, AD, Splunk, Shuffle and telemetry paths. | Provides the environment in which the scenario is executed. | Avoid attack narration and long firewall dumps; place full configuration in Appendix A/G. |
| 5. Controlled Offensive Scenario and Purple-Team Simulation | Explain the controlled offensive design and execution, trust-boundary and identity transitions, expected telemetry and validated outcomes. Treat replay automation as an important supporting engineering contribution. | Produces the observable behaviors consumed in Chapters 6–8. | Avoid making automation appear to be half the chapter's purpose; omit full commands, passwords and exploit recipes. |
| 6. Telemetry and Atomic Detections | Show how raw sources became normalized, testable detection hypotheses and OPS01 health monitoring. | Establishes the atomic signals composed in Chapter 7. | Avoid printing every SPL query; use representative logic and Appendix C. |
| 7. Correlation and SIEM Engineering | Explain entity/time-window correlation, cross-source evidence, campaign semantics, confidence and alert meaning. Keep scheduler/license/recovery work in one concise reliability subsection. | Converts atomic evidence into high-confidence inputs for SOAR. | Avoid letting licensing or troubleshooting appear to be a principal contribution. |
| 8. SOAR Response Engineering | Demonstrate cumulative engineering maturity from PB02 through PB05 using a shared reference architecture, lifecycle, playbook case views and an evolution matrix. | Shows how Chapter 7 alerts became progressively safer, richer and more verifiable response workflows. | Avoid four isolated workflow descriptions, node-by-node screenshots or treating PB01 as equivalent to PB02–PB05. |
| 9. Testing and Validation | Present expected versus actual results, negative tests, acceptance criteria and defensible metrics. | Supplies the evidence used for the discussion. | Avoid introducing new architecture or claiming percentages without defined denominators. |
| 10. Results and Discussion | Interpret what worked, why it matters, trade-offs, gaps and validity limits. | Synthesizes all earlier evidence rather than repeating it. | Avoid a second validation-results dump or vague praise of tools. |
| 11. Conclusion and Future Work | Answer the original questions and give a prioritized, evidence-based roadmap. | Closes the narrative. | Avoid new experiments, new literature review or unprioritized wish lists. |

### Placement of Core Concepts

- **MITRE ATT&CK:** introduced as a technique vocabulary in Chapter 2; applied
  in the attack matrix, detection catalog and traceability matrix.
- **Cyber Kill Chain:** introduced briefly in Chapter 2 and used only as a
  macro-phase overlay for the end-to-end scenario. ATT&CK remains the detailed
  mapping system.
- **NIST incident response:** introduced in Chapter 2; used to justify the
  detect/analyze/contain/recover lessons in Chapter 8.
- **Detection engineering:** defined in Chapter 2, operationalized in Chapters
  6 and 7, evaluated in Chapter 9.
- **SIEM and SOAR:** defined briefly in Chapter 2; deployed in Chapter 4;
  engineered in Chapters 6–8.
- **Active Directory and Windows attacks:** only the concepts required for the
  specific chain are introduced in Chapter 2; the actual implementation and
  results stay in Chapter 5.

## C. Reduced Core Diagram Inventory

Use a small toolset and export vector graphics as PDF. `draw.io` is best for
network/system diagrams; PlantUML is best for sequence and activity logic;
TikZ/PGF is best for small report-native flows and metrics; `pgfgantt` is best
for the project schedule. Existing Mermaid diagrams can remain source sketches
but should be exported to vector PDF or redrawn for the final report.

The target is twelve core technical figures plus one project Gantt. Evidence
screenshots are curated separately and do not inflate this inventory.

| ID | Diagram | Purpose and required elements | Report location | Priority | Tool and format |
|---|---|---|---|---|---|
| F01 | Segmented laboratory and trust boundaries | Merge deployment, zones, subnets, gateways and principal controlled paths into one readable view: VMware/GNS3, External, DMZ, Transit, VLAN 30, VLAN 50, OPNsense, R1, DVWA, AD, Windows, Splunk and Shuffle. NAT and detailed policy remain in T04. | Ch. 4 opening | Essential | draw.io; vector PDF |
| F02 | SOC evidence and response data flow | Sources -> syslog/forwarders -> Splunk indexes -> atomic/correlated detections -> Shuffle -> OPNsense/AD/endpoint -> verification/audit. | Ch. 4 monitoring section | Essential | draw.io or TikZ; vector PDF |
| F03 | Iterative purple-team methodology | Research/build -> simulate -> observe -> detect -> correlate -> respond -> verify -> improve, with evidence captured at each loop. | Ch. 3 methodology | Essential | TikZ; direct LaTeX |
| F04 | Internship engineering Gantt | Show the simplified ten-phase schedule and only evidence-backed milestones. | Ch. 3 closing | Essential project figure | `pgfgantt`; direct LaTeX/PDF |
| F05 | Controlled offensive scenario | Show the external-to-DMZ-to-Windows-to-AD progression, the `svc_web -> SYSTEM` identity boundary, Kerberoasting/valid-account use and persistence/C2 return path. | Ch. 5 opening | Essential | draw.io; vector PDF |
| F06 | Local privilege-escalation causal chain | Show `svc_web` writing the lab script, service start, protected wrapper, SYSTEM PowerShell and structured proof; annotate writer/executor SIDs and telemetry. | Ch. 5 privilege escalation | Essential | PlantUML sequence or TikZ; vector PDF |
| F07 | Detection-engineering pipeline | Raw telemetry -> normalization -> atomic detection -> correlation -> campaign -> SOAR trigger -> response -> independent verification. | Ch. 6 opening | Essential | TikZ; direct LaTeX |
| F08 | D13 cross-source correlation sequence | Demonstrate temporal/entity causality across DVWA, OPNsense and Windows evidence and show why isolated alerts are insufficient. | Ch. 7 representative case | Essential | PlantUML sequence; vector PDF |
| F09 | Shared SOAR reference architecture | Splunk alert, Shuffle intake, enrichment/case logic, analyst interface, response adapters, independent verification, audit and notification. | Ch. 8 opening | Essential | draw.io; vector PDF |
| F10 | Shared analyst-gated response lifecycle | Show investigation, classification, approval/refusal, fail-closed exits, scoped action, verification and recovery as one reusable lifecycle. | Ch. 8 common lifecycle | Essential | PlantUML activity; vector PDF |
| F11 | PB02-to-PB03 network/web response evolution | Two-panel view: PB02 establishes scoped reconnaissance response; PB03 adds web/network correlation, enriched outcome classification, CP routing, approval, multi-control OPNsense action and verification. | Ch. 8 PB02/PB03 | Essential | PlantUML activity or draw.io; vector PDF |
| F12 | PB04 identity-response workflow | Show D14/D15 normalization, I1–I4 assessment, IRP routing, stronger authorization, AD prechecks, temporary disable, Splunk verification and manual recovery. | Ch. 8 PB04 | Essential | PlantUML activity; vector PDF |
| F13 | PB05 layered endpoint/C2 workflow | Show D17/D18 campaign handling, P1–P4 assessment, CRP routing, native approval, exact endpoint and OPNsense actions, state termination and layered verification. | Ch. 8 PB05 | Essential | PlantUML activity; vector PDF |

### Optional Figures

Create these only if the relevant table cannot communicate the relationship
clearly:

| ID | Optional figure | Use only when |
|---|---|---|
| O01 | Attack/evidence timeline | The temporal relationship across the scenario remains unclear after F05, F08 and T06. |
| O02 | Atomic-to-correlation hierarchy | T10/T11 cannot clearly show how atomic detections feed D08/D13/D15/D18 and PB02–PB05. |
| O03 | Confirmed/Partial/Deferred result chart | The denominators are frozen and the chart adds meaning beyond the validation table. |

### Removed or Reclassified Views

- The standalone routing/NAT diagram is merged into F01 and T04.
- The separate correlation hierarchy and attack/detection timeline are optional,
  not mandatory.
- The standalone analyst-approved containment sequence is removed because F10
  and F11–F13 already show decision, action and verification ordering.
- The coverage chart is optional until its denominator is defensible.
- The Splunk executive dashboard is an evidence screenshot, not a technical
  diagram. It belongs in the curated evidence set.

### UML Decisions

- **Use-case diagram:** omit. Actors and permissions are clearer in a
  stakeholder/requirements table; a generic attacker/analyst/admin bubble
  diagram adds little technical value.
- **Component diagram:** do not create a separate UML component diagram. F02
  and F09 already explain components and interfaces more clearly.
- **Deployment diagram:** F01 performs this role. A second formal UML
  deployment view would duplicate the topology.
- **Sequence diagrams:** useful only for temporal causality. Use them for the
  SYSTEM transition and D13 correlation, not every attack or containment path.
- **Activity diagrams:** useful for branching SOAR decision logic and
  fail-closed behavior. They are not needed for reconnaissance or simple SPL.

## Gantt Chart Design

A Gantt chart is useful because this is an internship engineering project with
clear iteration and milestones. It belongs at the end of Chapter 3, after the
methodology, and should occupy one landscape page.

Use the official internship dates once confirmed. The ten rows should be:

1. Research, internship framing, scope and safety boundaries
2. Architecture and segmented-lab deployment
3. Controlled offensive scenario and replay automation
4. Telemetry onboarding and field normalization
5. Atomic detection engineering
6. Cross-source correlation and SIEM capability
7. SOAR foundation and reconnaissance response (PB01/PB02)
8. SOAR maturity progression across PB03, PB04 and PB05
9. Integrated validation, evidence consolidation and dashboard
10. Report and presentation production

Known evidence anchors include the initial vault baseline on 24 July 2026,
Phase 2 detection work by 31 July, Phase 3 work in early August, PB04 on
1 September, PB05 on 6 September, privilege-escalation validation on
9 September and license/dashboard validation on 10 September. These are not a
substitute for the official internship start/end dates.

Add milestone diamonds only for events that show real progression: first
end-to-end scenario, D13/D15/D18 validation, PB02 functional completion, PB03
CP3 verification, PB04 IRP3 acceptance, PB05 CRP4 acceptance,
`SVC_WEB_TO_SYSTEM_PROVED`, and full-dashboard restoration. Do not invent
percentage-complete values or fake day-level precision.

## D. Recommended Technical Tables

| ID | Table | Main body or appendix | Purpose |
|---|---|---|---|
| T01 | Objectives and measurable success criteria | Main, Ch. 1 | Make evaluation criteria explicit from the start. |
| T02 | Functional, security and non-functional requirements | Main, Ch. 3 | Connect design decisions to requirements. |
| T03 | Assets, addresses, roles and zones | Main, Ch. 4 | Make the topology readable without inspecting the diagram. |
| T04 | Trust boundaries, allowed paths and control rationale | Main, Ch. 4 | Explain segmentation and temporary exceptions. |
| T05 | Tool/technology selection rationale | Main, Ch. 4 | Compare roles and constraints, not marketing features. |
| T06 | Compact attack-stage matrix | Main, Ch. 5 | Summarize objective, path, ATT&CK, telemetry, detection and status. |
| T07 | ATT&CK technique mapping | Appendix B; short summary in Ch. 5 | Provide exact technique IDs without interrupting narrative. |
| T08 | Telemetry catalog | Main summary in Ch. 6; full version Appendix D | Map source, transport, index, sourcetype, events and limitations. |
| T09 | Detection catalog | Main highlights in Ch. 6; complete D/P1/OPS01 catalog Appendix C | Record ID, purpose, type, sources, severity, confidence, ATT&CK and validation. |
| T10 | Detection-engineering evolution by phase | Main, Ch. 6 closing | Show progression from source visibility and atomic rules to normalized multi-source correlations and operational health. |
| T11 | Correlation catalog | Main, Ch. 7 | Compare D08, D13, D15 and D18 entities, windows, stages, semantics and outcomes. |
| T12 | Operational reliability results | Ch. 9 main summary; details Appendix F | Show measured cadence, successful/failed/skipped runs, runtime and restoration lessons without making troubleshooting a core contribution. |
| T13 | PB02-to-PB05 SOAR evolution matrix | Main, Ch. 8 | Compare trigger quality, context, classification, approval, action, verification, failure behavior, recovery, reuse and auditability. |
| T14 | Response profiles and safety gates | Main summary; full Appendix E | Explain CP/IRP/CRP routes and why state-changing actions are constrained. |
| T15 | Reusable SOAR components and contracts | Main, Ch. 8 | Map shared schemas, lookups, NTF01, FW01, FW02 and restricted adapters to their playbook consumers. |
| T16 | Validation test matrix | Main summary; full Appendix F | Expected, actual, evidence and Confirmed/Partial/Deferred status. |
| T17 | Fail-closed/negative tests | Main, Ch. 9 | Prove unavailable services and invalid state do not reach writes. |
| T18 | Metrics and KPIs | Main, Ch. 9 | Present only measured and well-defined results. |
| T19 | Detection gaps and prioritized improvements | Main, Ch. 10 | Connect DG items to realistic mitigations and future work. |
| T20 | Full traceability matrix | Appendix F; compact view in Ch. 10 | Preserve end-to-end technique-to-validation traceability. |
| T21 | Evidence catalog | Appendix F | Map stable evidence IDs to claims, original filenames, storage and redaction status. |

### T10 — Detection-Engineering Evolution View

Use these columns:

```text
Engineering phase | Observable behavior | Telemetry introduced or corrected |
Atomic detections | Correlation/campaign logic | Validation/tuning outcome |
Engineering lesson
```

The rows should cover:

| Phase | Representative progression |
|---|---|
| Reconnaissance | OPNsense/Suricata/web evidence -> D01 and P1 rules -> P1-C01 source/campaign correlation |
| Web exploitation | DVWA and firewall evidence -> D02/D04–D07 -> D08 same-peer web-to-callback correlation |
| Pivot and internal access | Firewall, Suricata and Windows authentication -> D09–D12 -> D13 four-stage compromise correlation |
| Identity and credentials | AD Kerberos evidence -> D14 plus corrected D03 telemetry -> D15 credential-access-to-use correlation |
| Persistence and C2 | Windows process/PowerShell plus network flow -> D17 -> D18 endpoint/network correlation |
| Operational visibility | Splunk internal freshness/scheduler evidence -> OPS01 and measured search-reliability controls |

This table demonstrates detection maturity without pretending that every later
rule is inherently better than every earlier rule.

### T13 — PB02-to-PB05 SOAR Evolution Matrix

The final matrix should use the following dimensions. Statements marked for
workflow verification must be checked against the sanitized exports before
they become report claims.

| Capability | PB02 — Reconnaissance | PB03 — Web compromise | PB04 — Identity/AD | PB05 — Persistence/C2 |
|---|---|---|---|---|
| Primary trigger | Reconnaissance detection and scoped source/target context | Correlated web exploitation and callback evidence | D14/D15 identity evidence | D17/D18 persistence and C2 campaign evidence |
| Context reconstruction | Source-focused reconnaissance context | Web action, callback peer and DMZ context | Kerberos, account, authorization, logon and dependency context | User, host, Run value, process, callback and firewall state |
| Normalization/data contract | Early reusable event normalization; verify final fields from export | Normalized web/network entities and evidence bundle | Normalized D14/D15 schema and versioned identity case | Normalized D17/D18 campaign and endpoint/user case |
| Classification/routing | Reconnaissance assessment and scoped response route | Outcome classification and CP2/CP3 routing | I1–I4 assessment to IRP0–IRP4 | P1–P4 assessment to CRP0–CRP4 |
| Analyst role | Review/approval pattern before scoped containment; verify exact UI gate | Approval precedes state-changing OPNsense containment | Stronger approval for operationally risky AD action | Native authenticated approval for layered endpoint/network action |
| Containment scope | Validated source containment | Source block, callback block and scoped DMZ egress restriction | Exact temporary account disable for approved identity | Exact process and Run-value removal plus validated destination/PF-state control |
| Independent verification | Scoped network-control verification | Source/callback/egress state plus final audit and notification | Independent AD state and Splunk post-response observation | Endpoint state, OPNsense alias/PF state and campaign outcome verification |
| Fail-closed controls | Bounded scope; document verified preconditions from export | Decision and containment gates; document negative routes from evidence | AD and Splunk dependency outages stop before disable | CRP1 escalation and exact-object checks stop unsafe action |
| Rollback/recovery | Automatic rollback intentionally deferred | Automatic rollback intentionally deferred | Manual account recovery validated; automatic credential/session actions deferred | Evidence-preserving exact cleanup; broader host isolation and binary deletion deferred |
| Reusable components | Establishes response structure reused later | Strengthens reusable classification/notification/firewall patterns | Reuses shared notification and evidence patterns with identity-specific controls | Reuses NTF01/FW01/FW02 and a restricted endpoint adapter |
| Auditability | Functionally complete execution evidence | Final audit and notification | Versioned case, pre-action evidence and audit-before-cleanup | Versioned campaign case, authenticated decision metadata and layered final audit |
| Investigation/action separation | Emerging separation of assessment and scoped action | Classification/profile/approval precede containment | Explicit assessment, approval, precheck, action and recovery boundaries | Strongest separation across investigation, decision and restricted response workflows |

The prose around T13 must describe accumulated capabilities and lessons, not
score the playbooks with an artificial maturity percentage.

### Traceability Model

### Stable Identifier Strategy

Preserve existing identifiers wherever they already appear in Splunk, Shuffle,
filenames and Obsidian. Do not create a second alias for the same object.

| Artifact | Canonical convention | Examples and rules |
|---|---|---|
| Requirements | `REQ-F-xx`, `REQ-S-xx`, `REQ-NF-xx` | Functional, security and non-functional requirements |
| Attack stages | `ATK-01` through `ATK-11`, retaining `ATK-05A` | Mirror the existing attack-note numbering; mark `ATK-11` as supplemental rather than renumbering the core chain |
| Telemetry contracts | `TEL-<SOURCE>-<EVENT>` | `TEL-OPN-FILTER`, `TEL-SUR-EVE`, `TEL-WIN-4688`, `TEL-AD-4771` |
| Atomic/correlation detections | Keep existing `Dxx`, `P1-Rxx`, `P1-C01`, `OPS01` | D08, D13, D15 and D18 remain the canonical correlation IDs; classify them as `Correlation` rather than inventing duplicate `COR-xx` aliases |
| Playbooks | `PBxx`; append the route/profile when relevant | `PB03-CP3`, `PB04-IRP3`, `PB05-CRP4` |
| Validation tests | `VAL-<SCOPE>-<NN>` | `VAL-ATK-05A-01`, `VAL-D13-01`, `VAL-PB05-CRP3-01`, `VAL-NEG-PB04-01` |
| Evidence | `EV-<CLAIM>-<NN>` | `EV-ATK-05A-01`, `EV-D13-01`, `EV-PB05-CRP3-01`; retain the original screenshot filename in T21 |

The attack-stage mapping is frozen independently of chapter subsection numbers:

| Attack ID | Existing project stage | Narrative role |
|---|---|---|
| `ATK-01` | External reconnaissance | Initial external observation |
| `ATK-02` | DVWA web exploitation | SQL injection and enumeration |
| `ATK-03` | DMZ reverse shell | Command execution and DMZ compromise |
| `ATK-04` | DMZ-to-Windows pivot | Chisel pivot and WinRM access |
| `ATK-05` | Active Directory discovery | Internal and identity discovery |
| `ATK-05A` | Controlled local privilege escalation | `LAB\svc_web` writer to SYSTEM executor |
| `ATK-06` | Kerberoasting | Credential-access stage |
| `ATK-07` | Offline password recovery | Attacker-side validation with no central log expectation |
| `ATK-08` | Valid-account validation | Successful use of the recovered identity |
| `ATK-09` | Authorization assessment | Least-privilege boundary testing |
| `ATK-10` | Persistence and C2 simulation | Run value and reverse SOCKS channel |
| `ATK-11` | Controlled password spraying | Supplemental validation, not a forced core-chain stage |

The identifier is a report-level cross-reference, not necessarily a filename.
Every screenshot or log used in the report receives one EV ID in T21, which
maps to its original name and storage location. Labels in figures, tables and
captions must use the same canonical IDs.

Use one full master matrix in landscape orientation in Appendix F with these
columns:

```text
Requirement ID
Attack-stage ID
Objective
Source -> target asset/path
ATT&CK technique
Telemetry-contract ID and event
Atomic-detection ID
Correlation/campaign ID
SOAR playbook/profile
Response action
Verification-test ID and result
Validation status
Evidence ID
```

The main body should not reproduce this wide table. Use a compact seven-column
view in Chapter 10:

```text
Attack/technique | Asset path | Telemetry ID | Detection/correlation ID |
Playbook/route | Verification and evidence ID | Status
```

Chapter-level tables are filtered explanations of the same IDs, not independent
inventories. A stage without SOAR should show `Not applicable`, not a forced or
fictional playbook mapping.

The mandatory trace path is:

```text
ATK -> TEL -> atomic detection -> correlation -> PB/profile -> response
-> VAL verification -> EV evidence
```

If a stage legitimately has no central telemetry, correlation or playbook, use
`Not centrally observable` or `Not applicable`; never manufacture an object to
fill the chain.

## Attack-Chain Documentation Model

Use a combination of F05, F07 and T06. The fixed narrative template for each
attack phase is:

1. **Objective and precondition** — why the stage exists.
2. **Controlled action** — describe behavior and path, not an exploit recipe.
3. **Source, target and identity** — identify the trust-boundary crossing.
4. **ATT&CK mapping** — one or two justified technique IDs.
5. **Expected and observed telemetry** — name sources/events.
6. **Detection/correlation** — reference detection IDs instead of repeating SPL.
7. **Response relationship** — playbook/profile only where implemented.
8. **Validation result and limitation** — Confirmed, Partial or Deferred with
   evidence reference.

Commands, wordlists, payload syntax, credentials and repetitive terminal output
belong in Appendix B/G or are excluded entirely. The main chapter should explain
engineering causality, especially the two identity transitions:

```text
www-data -> LAB\svc_web remote access
LAB\svc_web file writer -> NT AUTHORITY\SYSTEM service executor
```

## Detection Engineering Documentation Model

The chapter should visibly implement this pipeline:

```text
Raw telemetry -> normalized fields -> atomic detection -> correlated detection
-> campaign identification -> SOAR trigger -> enrichment -> decision
-> response -> independent verification
```

For every detection in the catalog, record:

- ID and title;
- hypothesis/purpose;
- atomic, correlation or health classification;
- data sources and required fields;
- concise logic or pseudocode;
- severity and confidence rationale;
- ATT&CK mapping;
- false-positive conditions and tuning;
- schedule/window;
- validation status and evidence ID.

The main body should show short logic fragments or pseudocode for representative
rules only. Full SPL for D01–D18, P1 detections and OPS01 belongs in Appendix C.
Do not use a full-page query screenshot when a readable listing is available.

## SOAR Playbook Documentation Model

Use this recurring structure for PB02–PB05:

1. Purpose and incident scope
2. Triggering detections and input contract
3. Normalization and entity extraction
4. Enrichment and timeline/campaign reconstruction
5. Risk or outcome classification
6. Response profiles and decision logic
7. Analyst approval and safety gates
8. Containment actions
9. Independent verification
10. Audit, notification and case persistence
11. Rollback/recovery behavior
12. Validation results, fail-closed tests and limitations

F09 and F10 explain the shared architecture and lifecycle once. F11 gives PB02
and PB03 meaningful, connected treatment; PB03 must visibly carry the chain
from correlated detection through enrichment, classification, approval,
OPNsense containment and verification. F12 and F13 show how identity and
endpoint/C2 risk produced stronger controls in PB04 and PB05. T13 then compares
the same engineering dimensions across all four playbooks.

Use the recurring twelve-part structure above as an analytical lens, not a
requirement to give every playbook identical page length. For each playbook,
explicitly state which capability was retained, introduced, strengthened or
deferred relative to the previous one. PB01 is a short pre-history/lesson, not
a full parallel case study. Shuffle screenshots should prove only key states:
normalized input, analyst decision, authorized action, independently verified
result and audit record.

## Testing, Validation and KPI Strategy

Every test uses one row with:

```text
Test ID | Scenario/precondition | Expected result | Actual result |
Telemetry | Detection/correlation | Playbook/profile | Action |
Independent verification | Evidence | Status
```

### Meaningful Metrics

- **Observable-stage detection coverage:** detected observable stages divided
  by explicitly defined centrally observable stages. Offline cracking must not
  be counted as a Splunk failure.
- **Implemented correlation validation:** validated correlation searches over
  implemented correlation searches, with partial items shown separately.
- **Playbook acceptance results:** counts of routes/profiles that passed their
  acceptance criteria. Use counts rather than impressive-looking percentages
  when sample sizes are small.
- **Containment verification:** approved containment tests with independent
  state verification over approved containment tests executed.
- **Fail-closed control results:** negative tests that stopped before a state
  change over the negative tests executed.
- **Scheduler health:** successful, failed and skipped runs plus measured
  runtime for D13, D15 and D18.
- **Traceability completeness:** validated attack stages with a complete
  technique-to-evidence chain, using a defined denominator.
- **Detection or response latency:** only if source, index, alert, action and
  verification timestamps are exported and clocks are synchronized.

### Metrics to Avoid

- A false-positive rate derived only from attack traffic; there is not enough
  representative benign traffic.
- MTTD or MTTR calculated from a few manually initiated runs without consistent
  timestamp capture.
- Percentage risk reduction, ROI or maturity scores without a defensible model.
- A single overall success percentage that hides Partial and Deferred results.
- Counts of tools, alerts, screenshots or workflow nodes as quality metrics.

## Screenshot and Evidence Rules

The current named screenshot source is:

```text
C:\Users\DELL\Images\projects
```

It contains 94 candidate PNG files. Use the filenames as an initial evidence
index, then select only the images that prove important claims. Do not import
all 94 into Overleaf.

Main-body screenshots must prove an important claim that a diagram/table cannot
prove as well. Suitable examples are:

- one representative Splunk correlation result;
- the restored executive dashboard;
- the verified SYSTEM transition/proof result;
- one analyst approval state;
- one independently verified containment result;
- one fail-closed result if it supports a major safety claim.

Use approximately one or two evidence figures per major practical chapter,
not one per command or node. Each must be cropped, legible at page width,
annotated sparingly and captioned with the exact claim it proves. Captions should
include an evidence ID and system of origin.

Move the following to appendices:

- alternative/negative-run screenshots;
- complete saved-search and alert-setting pages;
- detailed Shuffle node configurations;
- full firewall rule pages;
- long console transcripts;
- supplementary before/after states.

Never include passwords, cookies, temporary approval URLs, API keys, license
identifiers, Kerberos ticket files/hashes or unnecessary personal data.

## E. Storytelling Strategy

The jury should follow one question through the report:

> Can a realistic multi-zone compromise be reproduced safely, observed,
> detected, correlated, investigated, handled through constrained response and
> independently verified?

The narrative is:

1. A segmented enterprise-like lab creates meaningful trust boundaries.
2. A controlled external attacker crosses those boundaries through a coherent
   attack chain rather than isolated demos.
3. Each stage generates an expected evidence contract.
4. Atomic detections provide local visibility but are insufficient alone.
5. Cross-source correlations reconstruct campaigns and reduce ambiguity.
6. High-confidence incidents trigger Shuffle, which enriches and investigates
   before any state-changing action.
7. PB02 through PB05 demonstrate accumulated maturity in context,
   classification, analyst involvement, safety, reuse and auditability.
8. Human approval, asset authorization and fail-closed gates constrain impact.
9. Response is accepted only after independent technical verification and an
   audit trail.
10. Negative tests and documented gaps demonstrate engineering honesty.
11. The results answer the objectives, while future work follows from measured
    gaps rather than adding more tools.

Chapter openings should state the engineering question; chapter conclusions
should answer it and introduce the next dependency. This keeps the report from
becoming a chronological diary or tool catalog.

## F. Overleaf and LaTeX Architecture

If the institution does not mandate a class/template, use LuaLaTeX with
`scrreprt`, A4 paper and 11- or 12-point text. `scrreprt` gives better chapter
and page-style control than the basic `report` class. If an official template
exists, it overrides this recommendation.

```text
report/
├── main.tex
├── latexmkrc                    # only if a custom build step is required
├── config/
│   ├── metadata.tex
│   ├── packages.tex
│   ├── colors.tex
│   ├── page-style.tex
│   └── listings.tex
├── frontmatter/
│   ├── titlepage.tex
│   ├── declaration.tex
│   ├── acknowledgements.tex
│   ├── abstract.tex
│   └── acronyms.tex
├── chapters/
│   ├── 01-introduction.tex
│   ├── 02-foundations.tex
│   ├── 03-requirements-methodology.tex
│   ├── 04-architecture.tex
│   ├── 05-attack-chain.tex
│   ├── 06-telemetry-detections.tex
│   ├── 07-correlation-siem.tex
│   ├── 08-soar-response.tex
│   ├── 09-validation.tex
│   ├── 10-results-discussion.tex
│   └── 11-conclusion.tex
├── appendices/
│   ├── app-a-architecture-config.tex
│   ├── app-b-attack-catalog.tex
│   ├── app-c-detection-catalog.tex
│   ├── app-d-telemetry-fields.tex
│   ├── app-e-soar-details.tex
│   ├── app-f-validation-evidence.tex
│   └── app-g-selected-listings.tex
├── figures/
│   ├── source/
│   │   ├── drawio/
│   │   ├── plantuml/
│   │   └── mermaid/
│   ├── pdf/
│   └── screenshots/
├── tables/
│   ├── requirements.tex
│   ├── assets-zones.tex
│   ├── attack-summary.tex
│   ├── detection-summary.tex
│   ├── playbook-summary.tex
│   ├── validation-summary.tex
│   └── traceability-master.tex
├── code/
│   ├── spl/
│   ├── powershell/
│   ├── bash/
│   ├── suricata/
│   └── firewall/
└── bibliography/
    └── references.bib
```

### Recommended Packages

- Typography/engine: `fontspec`, `microtype`, `setspace`
- KOMA page style: `scrlayer-scrpage`
- Figures: `graphicx`, `caption`, `subcaption`
- Tables: `booktabs`, `tabularx`, `longtable`, `array`, `siunitx`
- Landscape pages: `pdflscape`
- Lists: `enumitem`
- Color: `xcolor`
- Diagrams/charts: `tikz`, `pgfplots`, `pgfgantt`
- Code: `listings` with custom SPL, PowerShell, Bash and JSON styles
- Quotations/bibliography: `csquotes`, `biblatex` with `backend=biber` and an
  engineering-appropriate numeric/IEEE style
- Acronyms/glossary: `glossaries-extra`
- Links/references: `hyperref`, `bookmark`, `cleveref`

Prefer `listings` to `minted` unless syntax highlighting materially requires
Pygments; `listings` avoids a shell-escape dependency. Use `\appendix` instead
of adding an appendix package without a specific need. Do not mix KOMA with
`titlesec` or `fancyhdr`; use KOMA-native controls.

### Figure and File Rules

- Export architecture/workflow diagrams as vector PDF.
- Use PNG only for cropped UI evidence; avoid JPEG for text-heavy screenshots.
- Avoid direct SVG dependencies in Overleaf; convert SVG to PDF before upload.
- Keep editable diagram sources under `figures/source` and generated PDFs under
  `figures/pdf`.
- Use lowercase kebab-case names such as `fig-soc-data-flow.pdf`.
- Use label prefixes: `chap:`, `sec:`, `fig:`, `tab:`, `lst:`, `app:`.
- Reference every figure/table/listing in prose with `\cref{...}`.
- Keep captions outcome-oriented: state what the evidence demonstrates.
- Store bibliography entries in one `references.bib`; cite primary standards,
  vendor documentation and original research where possible.

## Visual Consistency and Accessible Notation

Every meaning must be encoded with color **and** at least one non-color cue such
as shape, border or line style. The figure must remain understandable in
grayscale and for readers with color-vision deficiencies.

| Meaning | Node/shape convention | Line convention | Color role |
|---|---|---|---|
| Attacker or offensive action | Sharp-cornered/hexagonal node with `ATK-*` label | Red dashed arrow with open arrowhead | Muted red |
| Infrastructure asset | Rounded rectangle; zone name always printed | Neutral solid connection | Zone fill: DMZ amber, Internal/AD blue, SOC purple, network gray |
| Telemetry source or event | Document/event shape with `TEL-*` label | Thin solid arrow | Teal |
| Atomic detection | Single-border detection block with canonical D/P1/OPS ID | Medium solid arrow | Violet |
| Correlation/campaign | Double-border block with D08/D13/D15/D18 ID | Bold solid or dot-dash arrow, explicitly labelled `correlates` | Dark violet |
| Analyst/manual decision | Diamond with actor/decision text | Manual branch labelled `approve`, `reject` or `review` | White fill, purple border |
| Automated response/containment | Action block with PB/profile ID | Heavy solid arrow with filled arrowhead | Dark navy/blue, deliberately different from attack red |
| Independent verification/audit | Check/document shape with `VAL-*` or `EV-*` label | Dashed return arrow toward the decision/audit state | Green |
| Deferred, refused or fail-closed path | Gray stop/terminal node | Gray dashed line ending at a bar or cross | Gray |

Never rely on red versus green alone. Print a grayscale test page before the
architecture is frozen. Put a compact legend on every full-page diagram and
label arrows with verbs such as `sends telemetry`, `correlates`, `approves`,
`blocks`, or `verifies`. Use the same asset names, IP formatting, canonical
IDs, line meanings and terminology across all figures. Tool logos may appear
sparingly, but labels and system roles remain the primary visual language.

## G. Main Body Versus Appendices

| Material | Main body | Appendix |
|---|---|---|
| SPL | Short representative logic and explanation | Complete versioned queries and alert settings |
| Suricata | One relevant example and result | Full custom/selected rules and configuration notes |
| PowerShell/Bash | Automation design and small safety excerpts | Selected scripts or links to versioned source; no secrets |
| Attack commands | Behavioral description only | Minimal sanitized reproduction details if academically necessary |
| Firewall configuration | Policy intent and representative rule | Full relevant NAT/rule/alias excerpts |
| Shuffle | Shared lifecycle, PB02-to-PB05 evolution and selected playbook decision diagrams | Workflow/node inventory, schemas and selected configurations |
| Webhook schemas | Important fields/data contract | Complete sanitized JSON schemas |
| Detection catalog | Representative rules and compact summary | Full D/P1/OPS01 catalog with SPL |
| ATT&CK | Stage-level summary | Complete technique/evidence mapping |
| Validation | Key test matrix and metrics | Full test cases, timestamps and supplementary outputs |
| Screenshots | Only decisive proof | Supporting UI and negative-path evidence |
| Raw logs/evidence | Never dump raw files | Referenced catalog or external evidence package, redacted |

## H. Missing Material Before Final Writing

### Confirmed Inputs

- The report will be written in English using LaTeX on Overleaf.
- Front matter will include the supplied title-page design, acknowledgements,
  Summary, Abstract, contents and the required lists.
- Chapter 1 will contain a concise CBI presentation and an Internship Framework
  (`Cadre de stage`) section.
- CBI does not require a confidentiality statement. Secrets, credentials,
  approval links and license identifiers must still be redacted.
- `C:\Users\DELL\Images\projects` is the candidate screenshot source; 94 named
  PNG files are available and will be curated rather than used wholesale.
- The password-spray Event `4771` telemetry gap is mitigated. Two failures and
  the D03 manual search are evidenced; only the current scheduled/trigger state
  requires final auditing.

### Required or High Priority

1. Obtain the title-page reference and logo assets from Mariam, and confirm the
   institution's page limit, font/margin rules, submission format and exact
   internship dates.
2. Confirm whether the Summary and Abstract must both be English or whether the
   institution expects a French `Résumé` followed by an English Abstract.
3. Validate the preserved privilege-escalation telemetry in Splunk before
   resetting the endpoint, or explicitly retain it as a Partial result.
4. Confirm Universal Forwarder inputs for Security, PowerShell Operational,
   System and Application and capture the ordered `4663/4688/4104/7036/9101`
   evidence if available.
5. Curate the 94 candidate screenshots and capture/index any missing final PB04,
   PB05 and D03 scheduler/trigger evidence using the existing
   naming scheme.
6. Export the accepted Shuffle workflows, lookups and custom PB05 endpoint app
   in sanitized form.
7. Export the final Splunk saved-search catalog, schedules, severity, sharing
   and enabled/disabled status.
8. Create a small metrics source table containing actual test counts,
   timestamps, scheduler results and acceptance status. Do not calculate MTTD or
   response latency until the necessary clocks/timestamps are verified.
9. Confirm final safe state: `svc_sql` enabled, temporary OPNsense aliases empty,
   and PB05 artifacts reset only after evidence collection.
10. Rotate the Brevo credential exposed during troubleshooting before declaring
    the environment closed.

### Needed for Presentation Quality

1. Confirm the final report title and institutional logo rules.
2. Recreate the essential diagrams in one visual system and retain their source
   files.
3. Build the master traceability matrix and assign stable test/evidence IDs.
4. Capture a clean executive-dashboard screenshot without browser clutter.
5. Record the official project schedule rather than inferring dates solely from
   file history.
6. Assemble primary references for MITRE ATT&CK, NIST incident response,
   Microsoft Windows events, Splunk, Suricata, OPNsense, Shuffle, GNS3 and
   VMware where each is actually discussed.

The report can be drafted before optional ticketing work. Ticketing should be
described as future work unless it is implemented and validated before the
results chapter is frozen.

## I. Critical Improvements and Deliberate Omissions

1. Replace the generic title with the engineering-focused working title above.
2. Do not organize chapters by tool. Organize them by problem, evidence pipeline
   and engineering outcome.
3. Keep theory short and make every concept justify a later design decision.
4. Use ATT&CK for detailed mapping and Kill Chain only for the macro narrative;
   do not duplicate two full mapping systems throughout the report.
5. Do not create a UML catalog. Omit use-case and standalone component diagrams;
   use only purposeful deployment, sequence and activity views.
6. Do not describe the attack as a command tutorial. Explain trust-boundary,
   identity, telemetry and control transitions.
7. Do not document all detections equally in the main body. Highlight D08,
   D13, D15, D18 and OPS01; move the full catalog to Appendix C.
8. Treat PB01 as an iteration/lesson, not an accepted result equivalent to
   PB04/PB05.
9. Separate attack success, detection success and response success. The local
   SYSTEM replay is proven; its Splunk correlation is still Partial.
10. Use counts for small validation samples. Avoid artificial percentages,
    MTTD/MTTR, false-positive rates and risk-reduction claims.
11. Make the full appendix traceability matrix the source of truth and use only
    readable summary views in chapters.
12. Prefer diagrams and tables for architecture/logic, but retain a small number
    of decisive screenshots as implementation proof.
13. Present limitations as engineering findings with consequences and next
    actions, not as apologies.
14. Keep optional Shuffle ticketing out of the critical path for the first
    report/presentation version.
15. Present PB02 through PB05 as cumulative response-engineering evolution,
    preserving the value of earlier playbooks while showing how later risk and
    validation requirements strengthened the architecture.

## Approval Gate Before Writing

Before creating `main.tex`, confirm:

- the working title;
- the supplied title-page design and institutional page constraints;
- official internship date range;
- whether the proposed eleven-chapter structure is accepted;
- whether Summary and Abstract are both English or use French/English pairing;
- whether the privilege-escalation Splunk validation will be completed before
  the first report freeze or documented as Partial.
