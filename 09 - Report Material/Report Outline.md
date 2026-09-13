# Report Outline

> [!note] Writing status
> The report is now being written in LaTeX on Overleaf. Read [[Report Writing Handoff]]
> before continuing. The complete chapter rationale, diagram and table
> inventories, storytelling model, appendix boundary, and evidence strategy are
> maintained in [[Report Architecture and Presentation Strategy]].

## Working Title

Engineering a Segmented Purple-Team Laboratory with Cross-Source Detection and
Analyst-Gated SOAR Response

## Front Page

- Mariam Ibni
- Université Sultan Moulay Slimane
- École Nationale des Sciences Appliquées de Khouribga
- Department: Cybersecurity and Intelligent Networks
- CBI
- CBI supervisors: Yassine Medouar and Othmane Menouar
- Academic supervisor: Samir Achraf Chemkar
- Final layout and logos to follow the reference supplied by Mariam

## Confirmed Front Matter Order

1. Title page
2. Institutional approval/declaration page, only if required
3. Acknowledgements
4. Summary
5. Abstract
6. Keywords
7. Table of contents
8. List of figures
9. List of tables
10. List of listings
11. List of acronyms and symbols

CBI does not require a confidentiality statement. Chapter 1 must include a
concise presentation of CBI and an Internship Framework (`Cadre de stage`)
section before the project problem and objectives.

## Chapters

1. Introduction and Project Framing
2. Technical Foundations and Design Rationale
3. Requirements, Threat Model and Engineering Methodology
4. Laboratory Architecture and Implementation
5. Controlled Offensive Scenario and Purple-Team Simulation
6. Telemetry and Atomic Detection Engineering
7. Cross-Source Correlation and SIEM Engineering
8. SOAR Orchestration and Response Engineering
9. Testing and Validation
10. Results, Discussion and Limitations
11. Conclusion and Future Work

## Important Figures

- F01 segmented laboratory and trust boundaries
- F02 SOC evidence and response data flow
- F03 iterative purple-team methodology
- F04 simplified internship engineering Gantt
- F05 controlled offensive scenario
- F06 local privilege-escalation causal chain
- F07 detection-engineering pipeline
- F08 D13 cross-source correlation sequence
- F09 shared SOAR reference architecture
- F10 shared analyst-gated response lifecycle
- F11 PB02-to-PB03 network/web response evolution
- F12 PB04 identity-response workflow
- F13 PB05 layered endpoint/C2 workflow

The executive dashboard, representative correlation result, SYSTEM proof,
analyst decision, verified containment and fail-closed outcome are curated as a
small evidence-screenshot set rather than additional architecture diagrams.

The controlled password-spray test is supplemental rather than a forced stage
in the linear compromise chain. Its Event 4771 telemetry and D03 manual search
are validated; only the current scheduled-alert/trigger state needs a final
audit.

The first report version should accurately separate the completed local SYSTEM
attack proof from its pending Splunk correlation validation. Optional Shuffle
ticketing and workflow refinements can be added in a later revision.

## Writing Principle

For each attack phase, present:

1. Objective
2. Preconditions
3. Controlled procedure
4. Result
5. Evidence
6. Detection
7. Gap
8. Defensive improvement
