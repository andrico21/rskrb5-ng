# Parity register for plan 2

## Purpose

This register belongs to plan 2 (`rskrb5-ng-parity`), the parity work that follows the
follow-up review of `6586b7a` ([`followup-6586b7a.md`](followup-6586b7a.md)). It holds every
plan-1 row that was transferred to plan 2, every defect found during plan 2 that is not fixed in
the same commit, every plan-1 residual that a plan-2 todo took over, and every critic finding of
the plan-2 critic pass. Every row ends with a final status backed by a proof.

## Method

Rows keep the columns of the plan-1 register. A row that plan 1 transferred keeps its plan-1 ID
and cites its plan-1 row. A new row takes the ID `FU-<AREA>-P<NN>` (for example `FU-TST-P01`),
numbered per area in the order the rows are added. Rows are sorted by ID, one row per line, and no
cell holds a pipe character.

## Status vocabulary

- `open`: not yet acted on (initial state of every row).
- `fixed`: fixed with a named proof (a failing-first test or a check) and commit.
- `dismissed`: shown not to be a defect, or not fixable in the place the row names; evidence recorded.

## Register

| ID | Sev | Title | Status | Proof | Behaviour change | Evidence or plan-2 todo |
| --- | --- | --- | --- | --- | --- | --- |
| FU-SVC-08 | nit | Built-in TransitPolicy represents one endpoint pair | open | none yet: closed by plan-2 todo 17 | none in plan 1 | transferred from plan-1 row FU-SVC-08 of `followup-6586b7a.md` (planner contested-row ruling); parity: capaths transited validation and multi-pair TransitPolicy; plan-2 todo 17 (WP-11). Existing TransitValidator remains the custom-policy extension. |
| FU-TST-06 | minor | AD password-reply interoperability is an open question | open | none yet: finalised by plan-2 todo 1 step 7 (lane 1E) | none; existing reply controls remain enforced | transferred from plan-1 row FU-TST-06 of `followup-6586b7a.md` (plan-1 todo-4 contested-row ruling); parity: Samba AD kpasswd reply interop; plan-2 todo 1 |
