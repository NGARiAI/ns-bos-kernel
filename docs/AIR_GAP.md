# Air-gap mode

`NGARI_AIR_GAP` is a policy setting read from the environment, not a security
boundary: whoever can edit the service's environment can turn it off. What it
does is make the kernel's own network calls stay on this machine by default,
and say so when they would not.

| Variable | Default | Meaning |
|----------|---------|---------|
| `NGARI_AIR_GAP` | `true` | `0`, `false`, `no` or `off` turn it off; case and spaces are ignored. Unset, empty, `1`, `true`, `yes` and `on` keep it on. Any other value keeps it on and logs a warning naming the accepted values. |

## What it refuses

With the gap on, the inference clients (`OllamaInterface`, `LlamaCppInterface`,
`VLLMInterface`) call loopback addresses only: `localhost`, any `127.x.x.x`
literal, `[::1]` and `[::ffff:127.x.x.x]`, with any port. Everything else is
refused: other addresses, every other name (`localhost.`,
`ollama.local`, `x.localhost`), the short form `127.1`, `0.0.0.0` and any
scheme but `http` and `https`. The host is read twice, as Python's URL parser
reads it and as the HTTP library will connect to it, and a URL on which they
differ is refused (`http://203.0.113.7\@127.0.0.1/` reads as `127.0.0.1` to
one and `203.0.113.7` to the other). The check looks at the URL's text and
resolves nothing; `localhost` is the one name ever handed to the resolver, and
`127.0.0.1` avoids even that.

A refused client is built without error and without a single request. It logs
one line at construction,

    air gap: refusing Ollama endpoint http://203.0.113.7:11434 (host 203.0.113.7
    is not a loopback address); set NGARI_AIR_GAP=0 to allow it

and every method then raises `AirGapError`, a `RuntimeError`, naming the same
endpoint and reason. The address is checked on every call, so a `base_url` changed after
construction cannot leave loopback. Messages carry `scheme://host:port` only,
never a user name or password from the URL.

`OllamaInterface.pull_model` is refused even for a loopback Ollama, because it
asks Ollama to download a model from its registry. `delete_model` is local and
unchanged.

Agent code needs bubblewrap: without it the sandbox's fallback runs the code in
a plain subprocess with the host's network, so with the gap on a missing
bubblewrap refuses the code (`sandbox_unavailable`) as if
`NGARI_SANDBOX_REQUIRE_BWRAP=1`. Install bubblewrap, set `NGARI_AIR_GAP=0`, or
pass `require_bwrap=False` to accept the fallback knowingly; that logs a second
warning. `get_capabilities()` reports `air_gap`.

`NetworkSynchronization.set_sync_mode` accepts `local_only` only; `peer_to_peer`,
`cloud_sync` and `hybrid` raise `AirGapError`. No sync code sends anything
today; the gate sits where the intent is declared.

A redirect from an engine is never followed, in either mode: the reply
reaches the caller as a failed call, and a warning names the endpoint. A
process listening on an engine's port could otherwise send each request,
prompt included, wherever its `Location` points.

A loopback call is never sent through an environment proxy (`HTTP_PROXY`,
`ALL_PROXY`), in either mode, so a proxy variable on the machine cannot route
`http://127.0.0.1:11434` off it.

## Overrides

`OllamaInterface(base_url, air_gap=False)` (and the other two clients) takes
the setting for one client over the environment's. When the environment says
on and the client says off, a warning names the endpoint.

`InferenceEngineManager.get_status()` reports `air_gap` and
`refused_endpoints`. The manager builds its clients on the default loopback
URLs, so the list is empty unless those defaults are changed. A LAN inference
box needs `NGARI_AIR_GAP=0`; there is no allow-list.

## What it records and reports

Each data plane start writes its `key_provider` audit entry with
`"air_gap": true` or `false`, so a start with the gap off is in the keyed
chain. The kernel logs `Air gap: on` at start, or, when it is off, a warning
naming what that allows: inference endpoints outside loopback, environment
proxies for those calls, model pulls, sync modes other than `local_only`, and
agent code run in a plain subprocess when bubblewrap is missing. The compliance report (`get_status()` carries it under
`data_sovereignty`) has an `air_gap` section: `on` and `source` (`environment`
or `default`) as of the call, and `host_interfaces` with the receive and
transmit byte counters of every interface but `lo`, read from
`/proc/net/dev`, and `since_start`, what those moved by since the data plane
started. An interface gone since then is listed as `gone`, since it may have
carried traffic, and a counter that went down is marked `reset`, with what it
holds now as the least that moved. The counters are shared with every process on the machine. This
measures; it does not verify that nothing left the box. `data_sovereignty`
stays about the data (audit, key, telemetry) and does not depend on this
setting.

## What it does not cover

Other processes on the host, the inference engine's own network traffic (an
Ollama that fetches models by itself), and anything the application does
outside this library.

## Upgrading

A client built on a non-loopback engine URL, a `pull_model` call, a sync mode
other than `local_only`, or a box without bubblewrap stops after the upgrade
until `NGARI_AIR_GAP=0` is set or the cause is fixed.
