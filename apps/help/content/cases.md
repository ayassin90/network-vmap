# Cases
pages: alerts:cases alerts:case alerts:case_new
group: Operations
order: 41
A case tracks one problem from first alert to fix: who owns it, what was found, what was changed, and which devices were involved.

## fields: Status, priority and owner
- **Status**: New → In progress → Waiting (on a vendor, a change window, a user) → Resolved → Closed.
- **Priority**: P1 critical (service down) to P4 low.
- **Assignee** and **due date** make ownership clear. "Mine" on the case list shows yours.
Every change of status, priority or owner is written to the timeline automatically.

## timeline: Timeline notes
Add a note for every step: what you checked, what you found, what you changed. The timeline is the record of the case for whoever picks it up next.

## resolve: Resolving
When you set a case to Resolved you can resolve its linked alerts at the same time. If the problem is still there, the next collection raises a fresh alert.
