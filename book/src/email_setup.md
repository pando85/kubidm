# Outgoing Email

> "All services evolve to the point they eventually can send email" - some wise nerd, probably.

Kubidm can be configured to optionally send messages to users. This is important for features such as sending credential
reset links.

## Architecture

Kubidm maintains a message queue in its database. This allows all servers to queue messages to be sent to users. Each
queued message is sent _at least_ once.

`kubidmd` itself does not send the messages, but relies on an external tool, `kubidm-mail-sender` to process the mail
queue. It is recommended you only run a single instance of the `kubidm-mail-sender` to prevent duplicate mail
transmission.

## Install Kubidm Mail Sender

`kubidm-mail-sender` is part of the `kubidm/tools` container. Alternately it should be provided by the `kubidm-server`
package if you are using a distribution source.

## Mail Sender Service Account

`kubidm-mail-sender` requires a service account that is part of `idm_message_senders` group.

```bash
kubidm service-account create <ACCOUNT_ID> <display-name> <entry-managed-by>
kubidm service-account create mail-sender "Mail Sender" idm_admins

kubidm group add-members idm_message_senders mail-sender
```

The service account must have an api token with read-write privileges.

```bash
kubidm service-account api-token generate ACCOUNT_ID LABEL [EXPIRY] --readwrite
kubidm service-account api-token generate mail-sender "mail sender token" --readwrite
```

> [!WARNING]
>
> The mail-sender service account should only be a member of `idm_message_senders` - never add them to any other group -
> use another account for other purposes!

## Configuration

```toml
{{#rustdoc_include ../../examples/mail_sender.toml}}
```

## Running the Mail Sender

You should test the mail sender configuration by sending an email with:

```bash
docker run .... kubidm/tools:latest \
    /sbin/kubidm-mail-sender \
    -c /data/kubidm/config \
    -m /data/kubidm/mail-sender \
    -t test@example.com
```

If successful, you can run `kubidm-mail-sender` with:

```bash
docker create .... -n kubidm-mail-sender kubidm/tools:latest \
    /sbin/kubidm-mail-sender \
    -c /data/kubidm/config \
    -m /data/kubidm/mail-sender
docker start kubidm-mail-sender
```

## Message Queue Management

The message queue can be managed by members of the group `idm_message_admins`. By default this privilege is inherited by
`idm_admins`.

You can insert a test message into the queue with:

```bash
kubidm system message-queue send-test-message TO_ACCOUNT
kubidm system message-queue send-test-message ellie
```

Once inserted, the message can be viewed in the queue.

```bash
$ kubidm system message-queue list

message_id:   0a9318dc-920f-4944-9ce4-91b4322b5dad
send_after:   2026-02-18 2:49:43.163072 +00:00:00
sent_at:      queued
delete_after: 2026-02-25 2:49:43.163072 +00:00:00
template:     test_message_v1
to:           ellie@example.com
```

Once the message has been successfully processed, it will be moved to the sent state.

```
kubidm system message-queue list

message_id:   0a9318dc-920f-4944-9ce4-91b4322b5dad
send_after:   2026-02-18 2:49:43.163072 +00:00:00
sent_at:      2026-02-18 2:52:48.733806 +00:00:00
delete_after: 2026-02-25 2:49:43.163072 +00:00:00
template:     test_message_v1
to:           ellie@blackhats.net.au
```
