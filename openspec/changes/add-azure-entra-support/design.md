# Design: Azure Entra ID Audit + Sign-In Log Support

## Data Flow

## Log Schemas

### Entra Audit Log

### Entra Sign-In Log

## Parser Design

### LogType strings

### Event normalization (Entra -> cloudtrail.Event)

## Classifier Registration

## Ingestion

### Option A: Event Hubs direct (new mode)

### Option B: Lambda/Function forwarder to SQS (reuse existing mode)

## Rules

### Hand-written (critical detections)

### Ported from Panther/Elastic

## Config Surface

### New flags / env vars

## Security

## Backwards Compatibility
