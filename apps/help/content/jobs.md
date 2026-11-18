# Jobs
pages: jobs:list jobs:detail
group: Operations
order: 43
A job is one task against one device: a collection, a poll, a connection test, a command run or an upgrade step.

## where: Who runs a job
Jobs for devices without a collector run on this server's worker. Jobs for devices with a collector wait until that collector picks them up. A collector job that is not picked up within a day is cancelled.

## reading: Reading a job
The job page shows the raw output of every command, any errors, and the job specification with passwords hidden. Use it to understand a failed collection: "Authentication failed" means the credential, "timed out" or "unreachable" means routing, ACLs or the device's SSH settings.
