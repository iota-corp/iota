# Design: Azure Resource Diagnostic Settings Log Support

## Data Flow

## Log Schemas

### Azure Activity Log (control plane)

### Azure Resource Logs (data plane, per resource type)

## Parser Design

### LogType strings

### Event normalization (Azure -> cloudtrail.Event)

### Handling schema variation across resource types

## Classifier Registration

## Ingestion

### Option A: Event Hubs direct (new mode)

### Option B: Lambda/Function forwarder to SQS (reuse existing mode)

### Diagnostic Settings export configuration

## Rules

### Hand-written (critical detections)

### Ported from Panther/Elastic

## Config Surface

### New flags / env vars

## Security

## Backwards Compatibility
