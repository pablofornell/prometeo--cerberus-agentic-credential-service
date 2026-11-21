import { defineMessages } from "../i18n";

/** Strings of remote mode (ADR-0034) that the unlock screen, Settings and the shell share. */
export const messages = defineMessages({
  "connect.open": "Connect to a remote server",
  "connect.title": "Connect to a remote server",
  "connect.desc": "Work with a vault that runs on a server with cerberusd. This desktop then opens no vault of its own and serves no local agents.",
  "connect.steps": "On the server, run cerberusd admin enroll. Move the bundle file it writes to this computer over a trusted channel (for example scp), then choose it here.",
  "connect.choose": "Choose bundle file",
  "connect.choose.title": "Choose the Cerberus admin bundle",
  "connect.failed": "Cannot import the bundle",
  "connect.check.title": "Compare before you connect",
  "connect.check.body": "Run cerberusd status on the server. Its CA pin and CA SHA-256 must be exactly the ones below. If they differ, do not connect.",
  "connect.delete": "Delete the bundle file after the import: it holds the key of this desktop.",
  "connect.restart": "Cerberus restarts to connect. Unlock then with the phrase of the bound operator.",
  "connect.go": "Connect",
  "connect.lockAndGo": "Lock and connect",
  "connect.back": "Choose another file",
  "connect.cancel": "Cancel",
  "connect.failedActivate": "Cannot connect",

  "fact.server": "Server",
  "fact.url": "Address",
  "fact.pin": "CA pin",
  "fact.sha": "CA SHA-256",
  "fact.operator": "Bound operator",
  "fact.expires": "Certificate valid until",
  "fact.expires.days": "{date} ({n} days left)",
  "fact.expires.soon": "{date} ({n} days left, enrol this desktop again soon)",
  "fact.expires.past": "{date} (expired)",
  "fact.version": "Server version",

  "local.use": "Use the local vault",
  "local.use.failed": "Cannot switch to the local vault",

  "unreachable.title": "Cannot reach {label}",
  "unreachable.retry": "Try again",
  "pin.title": "The server is not the one you enrolled with",
  "protocol.title": "The server does not match this desktop",
  "revoked.title": "The server no longer accepts this desktop",
  "revoked.body": "Its enrolment was revoked or its certificate expired. Enrol it again on the server with cerberusd admin enroll, then import the new bundle.",
});
