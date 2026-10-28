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

The command fails without changing anything if the origin is not a `pull` or `mutual-pull` supplier of this node.
