# Reporting a weakness in Shield

Shield is an evidence system. A defect here does not leak data — it produces a
record that is worth less than it appears to be, which is worse. Attacks are
welcome and wanted.

## What we want to hear about

- A way to get a record sealed that misrepresents the physical world.
- A way to alter, insert, remove or reorder custody history without the chain
  breaking.
- A way to make the evidence export verify when it should not, or to make an
  independent verifier disagree with the service.
- A place where the product, the docs, or the certification **claims more than
  it can show.** This counts as a security defect here, not a copy edit.

## What is already known

Read `audit/accepted-risks.md` first. Those limits are documented deliberately
and we are not looking for them to be re-reported — most importantly **AR-1:
Shield cannot prove a photo came off a camera sensor**, and EXIF is forgeable
in about twelve lines using the same library Shield reads it with. We
demonstrated that against our own product.

If you can show a documented limit is **worse than described**, that is a new
finding. Say exactly how it exceeds the entry.

## How to report

Open an issue, or contact the maintainer privately if the finding would let
someone forge a record before it is fixed. Include what you sent, what you got
back, and why it should not have worked.

## What we will do

- Acknowledge within **three working days**.
- Tell you our assessment, including if we think you are wrong and why.
- Fix it, add a regression test **and a permanent invariant** naming the attack
  it prevents, and record it in `audit/ATTACKS.md` — whether it came from you,
  from the daily audit, or from us.
- Credit you unless you ask us not to.

There is no bounty yet. There will be when there is revenue; until then the
honest offer is a fast response, public credit, and a fix you can verify.
