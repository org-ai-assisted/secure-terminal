#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Command-hook protocol: call an external handler to judge a command before it
runs.

secure-terminal ships no policy and no AI -- only this hook. The handler (a
script, or a pipe to an AI, configured by the user) receives the command as a
JSON object on stdin and replies with a verdict as JSON on stdout. All judgment
lives in the handler; this module only speaks the protocol, contains the
handler's errors, and sanitizes anything the handler asks to show or suggest, so
a confused or hostile handler cannot inject escape sequences or auto-run a
command.

Request (stdin): {"version":1,"command":..,"cwd":..,"tab":..,"transcript":..?}
  or, for a multi-line injected payload judged as ONE unit (ctl-send-text):
                 {"version":2,"command":..,"script":..,"cwd":..,"tab":..,
                  "transcript":..?}
Reply (stdout):  {"verdict":"allow|block|ask|need_transcript",
                  "message":..?,"suggestion":..?,"multiline_reviewed":..?}

Version 2 adds `script`: the WHOLE multi-line payload, judged once against the state
at injection time (no per-line stale-state race). A version-2 handler reads `script`,
reasons over the whole thing, and -- to have an ALLOW trusted -- MUST set
`multiline_reviewed: true` in its reply. `command` mirrors `script` for a handler that
still reads `command`, but an ALLOW without the ack is NOT trusted for a multi-line
batch (a version-1 handler judges only the single-line `command`, so a
`startswith`/`^`-anchored rule would miss a dangerous later line): the caller fails
CLOSED and refuses the batch. `block`/`ask` are always honored.

A reply of need_transcript triggers a second call with the transcript attached
(the cheap-then-escalate pass), so the expensive/long/injection-prone transcript
is only sent when the handler asks for it. Any handler error, timeout or
malformed reply falls back per on_error ('allow' with a visible note, or
'block').
"""

import json
import subprocess
from typing import TypedDict

from secure_terminal.sanitize import render_output, sanitize_paste

VERDICTS = ('allow', 'block', 'ask')


class HookResult(TypedDict):
    """The decision evaluate() always returns: a fixed shape so a caller can rely
    on `suggestion`/`message` being str (never the `error` bool) at the read site."""
    verdict: str
    message: str
    suggestion: str
    error: bool


def _sanitize_message(text):
    """Advisory text is DISPLAYED, so strip escapes and non-ASCII and cap it."""
    if not text:
        return ''
    return render_output(str(text), 'box')[:2000]


def _sanitize_suggestion(text):
    """A suggested command may be SENT to the shell, so reduce it to a single
    line of printable ASCII -- a handler can never smuggle control bytes or a
    trailing newline (which would auto-run) into a suggestion."""
    if not text:
        return ''
    safe = sanitize_paste(str(text)).replace('\r', ' ').replace('\t', ' ')
    return safe[:1000].strip()


def _invoke(handler_argv, payload, timeout):
    proc = subprocess.run(
        list(handler_argv), input=json.dumps(payload).encode('utf-8'),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    raw = proc.stdout.decode('utf-8', 'replace').strip()
    return json.loads(raw) if raw else {}


def _error(on_error, why) -> HookResult:
    verdict = 'block' if on_error == 'block' else 'allow'
    tail = ' (blocked)' if verdict == 'block' else ' (allowed)'
    return {'verdict': verdict, 'message': why + tail, 'suggestion': '',
            'error': True}


def evaluate(handler_argv, command, timeout=10, on_error='allow',
             cwd='', tab='', script=False, transcript_provider=None) -> HookResult:
    """Run the handler for `command` and return a decision:
    {'verdict': 'allow'|'block'|'ask', 'message': str, 'suggestion': str,
     'error': bool}. transcript_provider, if given, is called only when the
    handler replies need_transcript. With script=True, `command` is a MULTI-LINE
    payload judged as one unit: the request is version 2 with an explicit `script`
    field (and `command` mirrors it, so a version-1 handler still sees the content
    and cannot fail open on an empty command)."""
    payload = {'version': 2 if script else 1, 'command': command,
               'cwd': cwd, 'tab': tab}
    if script:
        payload['script'] = command
    try:
        reply = _invoke(handler_argv, payload, timeout)
        if isinstance(reply, dict) and reply.get('verdict') == 'need_transcript':
            payload['transcript'] = (transcript_provider() if transcript_provider
                                     else '')
            reply = _invoke(handler_argv, payload, timeout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return _error(on_error, 'command hook error: ' + str(exc))
    if not isinstance(reply, dict) or reply.get('verdict') not in VERDICTS:
        return _error(on_error, 'command hook returned an invalid verdict')
    result: HookResult = {
        'verdict': reply['verdict'],
        'message': _sanitize_message(reply.get('message')),
        'suggestion': _sanitize_suggestion(reply.get('suggestion')),
        'error': False}
    if (script and result['verdict'] == 'allow'
            and reply.get('multiline_reviewed') is not True):
        # A multi-line batch was sent, but the handler did not confirm it reviewed the
        # whole `script` (a version-1 handler judges only the single-line `command`, so
        # its ALLOW can miss a dangerous later line -- e.g. a `startswith`/`^`-anchored
        # rule sees only the first line). Fail closed: refuse the batch rather than
        # trust an unconfirmed allow. A handler opts in by reading `script` and setting
        # `multiline_reviewed: true` in its reply.
        return {'verdict': 'block',
                'message': _sanitize_message(
                    'command hook did not confirm multi-line review; refusing the '
                    'injected batch (upgrade the hook to read the "script" field)'),
                'suggestion': '', 'error': False}
    return result
