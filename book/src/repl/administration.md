# Administration

## Renew Replication Identity Certificate

The replication identity certificate defaults to an expiry of 4 years (1460 days).

To renew this run the command:

```bash
docker exec -i -t <container name> \
  kubidmd renew-replication-certificate
# certificate: "MII....."
```

You must then copy the new certificate to other nodes in the topology.

> [!NOTE]
>
> In the future we will develop a replication coordinator so that you don't have to manually renew this. But for now, if
> you want replication, you have to do it the hard way.

## Refresh a Lagging Consumer

If a consumer has been offline for more than 7 days, its error log will display that it requires a refresh.

You can manually perform this on the affected node.

```bash
docker exec -i -t <container name> \
  kubidmd refresh-replication-consumer
```

The command asks for confirmation with `--i-want-to-refresh-this-servers-database`. By default the refresh is taken by
whichever supplier answers first. To choose the source, add `--from` with the replication origin of the supplier as it
appears in this node's replication configuration:

```bash
docker exec -i -t <container name> \
  kubidmd refresh-replication-consumer --i-want-to-refresh-this-servers-database \
  --from repl://node2.example.com:8444
```

The command fails without changing anything if the origin is not a `pull` or `mutual-pull` supplier of this node, or if
it matches more than one of them. A server that predates `--from` never refreshes from any supplier in its place: it
does not understand the request, and the command waits without an answer until it is interrupted.

A refresh that cannot start within 15 seconds, for example because the supplier does not resolve or cannot be reached,
is reported as failed and is dropped: it does not run later when the supplier comes back. Run the command again once the
supplier is reachable.

## Troubleshooting: Dangling Required References

A reference is dangling when the entry it points to does not exist, for example after a bug, a manual database repair,
or when one node deletes a group while another node makes it the only receiver of an access control profile. Replication
removes dangling references from optional attributes. When a dangling reference is the only value of a required
attribute, removing it would make the entry invalid and fail the refresh or the incremental replication every time.
Replication keeps that value instead, so that the node can always catch up.

### How They Appear

The node that applies the replicated content logs an error for each kept reference:

```text
Keeping a dangling reference in a required attribute: its target is missing. ... | source_entry_uuid: 840065a2-...
| source_entry: my_policy | attribute: approver | missing_target_uuid: 96ddb5ba-...
```

Database verification (`kubidmd database verify`) reports it as `RefintNotUpheld`, with the entry, the attribute and the
missing target. A reference to an entry that is in the recycle bin is reported too.

### Why They Are Kept

- **It fails closed.** A dangling reference resolves to nothing, so it grants nothing: an access control profile whose
  receiver group is missing applies to nobody, an approver slot that points to nobody can not be filled, and an
  application whose linked group is missing grants access to nobody.
- **It is the same on every node.** The entry stays live and unchanged, so the nodes do not diverge, and an
  administrator can fix it on any node.
- **The uuid can not be reused.** While the reference dangles, the server refuses to create an entry with the uuid of
  its target, which would otherwise receive what the reference grants. This applies to every create with a uuid in the
  dynamic range, including the entries created by a sync connector. Before its tombstone is purged, the uuid of a
  deleted entry can not be reused anyway.
- **A recycled holder only blocks the uuid for a while.** An entry that holds the dangling reference and is then deleted
  keeps blocking the uuid on the node that deleted it. Replication only keeps the value on live entries, so once the
  deletion replicates the value is removed and the uuid is no longer blocked. Reviving such a holder then fails, because
  its required attribute is empty.

### How to Fix Them

Modify the entry so that the required attribute references an entry that exists, or delete the entry if it is no longer
needed. The change replicates like any other.

- **Revive the target.** If the missing target is still in the recycle bin, reviving it makes the reference valid again
  and restores what it grants, including the members the target had before it was deleted. Check that this is what you
  want before you revive it.
- **Approval policies can not be modified.** To fix a policy whose approver dangles, delete the policy and create it
  again.
- **A local delete can leave a dangling value.** While a dangling value remains in a required attribute, deleting the
  last _live_ value of that attribute succeeds, as the attribute is not empty. The entry then only holds dangling
  values: fix it as above.

### Known Gaps

- A conflicted uuid that is the last value of a required reference still stalls replication. This predates the handling
  of dangling references. Keeping the value would make it resolve to the winner of the conflict, which is not what the
  reference meant.
- A dangling key provider reference never commits, because the keys are reloaded before the database commit. Only the
  internal key provider exists, so this can not happen in practice.
