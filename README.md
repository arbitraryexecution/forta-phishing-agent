# Suspicious Approvals Agent

## Description

This agent detects when many Approval events occur from Externally Owned Accounts (EOAs) to a common EOA.  While this behavior is common for the functionality of centralized exchanges, it is anomalous for the ordinary operation of other blockchain transactions.  Therefore, it may be an indication that a phishing attack, similar to the BadgerDAO attack of December 2021, may be occurring.

## Supported Chains

- Ethereum

## Alerts

- AE-SUSPICIOUS-APPROVALS
  - Fired when more than 10 Approval events occur from EOAs to a common EOA 
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata includes owner addresses and the token addresses that they approved to the common EOA

## Test Data

The agent behavior can be verified by running against the following block range, corresponding to the beginning of the BadgerDAO phishing attack:

- 13650638 - 13652300
