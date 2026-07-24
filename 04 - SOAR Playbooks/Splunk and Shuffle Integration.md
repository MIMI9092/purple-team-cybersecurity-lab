# Splunk and Shuffle Integration

## Architecture

```text
Splunk scheduled alert
        |
        | HTTP webhook
        v
Shuffle workflow
        |
        | Splunk REST API query
        v
Splunk management API: 10.10.50.10:8089
```

## Completed Workflow

1. A Shuffle workflow named `Splunk Alert Receiver` was created.
2. A webhook trigger was started.
3. Splunk was configured to send scheduled-alert results to the webhook.
4. A manual POST successfully created a Shuffle execution.
5. Shuffle used an HTTP action to query Splunk.
6. The Splunk API initially returned `401 Unauthorized`.
7. Correct credentials were configured without storing them in this vault.
8. The API returned HTTP `200` and related OPNsense events.
9. A real Splunk scheduled alert successfully triggered Shuffle.

## Confirmed Payload Fields

The Splunk webhook included:

- Search SID
- Search name
- Application
- Owner
- Results link
- Result object
- Host
- Source
- Sourcetype
- Raw event

## Current Enrichment

Shuffle receives the alert and performs additional Splunk searches using fields from the webhook payload.

## Planned Improvements

- Normalize alert fields.
- Assign severity.
- Map MITRE technique and CKC phase.
- Add source and destination zones.
- Add account and host enrichment.
- Create a case.
- Notify the analyst.
- Require approval before containment.
- Add temporary, reversible OPNsense blocking.
- Record every automated action.

## Reliability Lesson

Shuffle requires sufficient RAM for OpenSearch. When memory was exhausted, the backend and Orborus exited. Increasing available memory and restarting the stack restored operation.
