# What the kernel accepts from agents and models

Agents hand the kernel names, tasks, results, messages and layouts, and a
model's replies can call tools. Both are untrusted: an agent can be wrong,
and a model can be steered by any document it reads. This page lists what
the kernel takes, what it refuses, and what it changes on the way in, so an
application meets these as documented limits rather than surprises. The
sandbox that agent code runs in is `SANDBOX.md`.

## Agents, tasks and messages

`core/kernel/agent_runtime`; `NSBOSKernel.register_agent`, `create_task` and
`publish_event` pass through to it.

| What | Accepted | Otherwise |
|------|----------|-----------|
| An agent's name and type | Non-empty strings, at most 256 bytes each in UTF-8 | `TypeError` or `ValueError`, nothing saved |
| An agent's version, description and environment, together | At most 4 KiB of JSON, nested at most 64 deep | `ValueError`, nothing saved |
| A task's agent id and action | Non-empty strings, at most 256 bytes each in UTF-8 | `TypeError` or `ValueError`, nothing saved |
| A task's payload | At most 256 KiB of JSON, nested at most 64 deep | `ValueError`, nothing saved |
| A message, published on a topic | At most 256 KiB of JSON, nested at most 64 deep | `ValueError`, nothing written |
| A topic | A non-empty string with no `/` or NUL, at most 214 bytes in UTF-8 | `ValueError` |

A topic names the files its messages are kept in, and 214 bytes is the
longest whose files still fit a 255-byte file name, with state encryption on
or off. The length is checked to publish only: messages an earlier kernel
wrote on a longer topic are still read.

Each refusal comes before anything is saved or recorded in the audit chain,
so every agent and task on disk has its audit entry.

A task's result is stored as the task file can hold it: tuples become lists,
and values JSON cannot hold become their text. A result over 256 KiB, nested
more than 64 deep, or impossible to write at all (keys that are not strings,
a number too long) is stored as
`{"error": "the result could not be stored"}`. The task still completes, and
every other task can still be saved.

Each subscriber to a topic gets its own copy of a message, as it was stored,
so one subscriber cannot change what the next receives. A callback that
subscribes while a message is being delivered gets the next message, not
that one.

Names, actions, topics and error text an agent supplies are written to the
kernel's log as their `repr`, cut to 200 characters (500 for an error), so a
newline in them cannot start a line that reads as the kernel's own.

## Tool calls from a model

`OllamaInterface.chat_with_tools` and `InferenceEngineManager.chat_with_tools`
run the loop: the model replies, its tool calls are dispatched, the results
go back, until it answers without one.

- Only calls to tools the caller declared reach the dispatcher. Undeclared
  ones are dropped with one warning per reply that gives their count and
  the first three names, each cut to 64 characters.
- At most `max_tool_calls` calls are dispatched in all, over every round:
  16 by default. Calls past it are dropped in order, and a reply asking for
  more once none are left ends the loop, its content ending in
  `[_tool_calls_exceeded]`. `max_iterations` (4 by default) bounds the
  rounds the same way, ending in `[_iterations_exceeded]`.
- A reply or tool result the loop cannot read (nested too deep, a number
  too long) is kept as the text it was, and a value of the wrong type
  (`tool_calls` that is not a list, a name that is not a string) is no
  call; neither raises. A request that fails in a later round returns the
  history of the calls that ran, so the caller always knows which tools
  have run.
- A dispatcher that raises, or returns anything but a list of messages,
  ends the loop with the history of the rounds before, its content ending
  in `[_tool_dispatch_failed]`. Which calls of that round ran is the
  dispatcher's to say.

Outside the tool loop, each engine's `generate`, `chat` and `list_models`
give the empty answer a failed call gives for a reply they cannot read,
nested too deep included. In a streamed reply, a line that is not a JSON
object is skipped, and the text before and after it is kept.

## Generative UI

`core/kernel/generative_ui`.

| What | Accepted | Otherwise |
|------|----------|-----------|
| A component type, in an imported layout | A lowercase letter, then lowercase letters, digits or `-` | Import returns `False` |
| A platform, for `generate_layout` | No `_` in it | `ValueError` |
| A layout id or user id | Its file name, `<id>.json`, at most 255 bytes, with no `/` or NUL | `ValueError`; import returns `False` |

A layout's id joins its context and platform with `_`, so a platform without
one gives every id a single reading. A component type becomes a class name
in the HTML; a layout built in code, or saved by an earlier kernel, with any
other type renders it as `unknown`. A new layout or behaviour record is kept in memory only once it
is saved.
