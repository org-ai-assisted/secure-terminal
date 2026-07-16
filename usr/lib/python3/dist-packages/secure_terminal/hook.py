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
Reply (stdout):  {"verdict":"allow|block|ask|need_transcript",
                  "message":..?,"suggestion":..?}

A reply of need_transcript triggers a second call with the transcript attached
(the cheap-then-escalate pass), so the expensive/long/injection-prone transcript
is only sent when the handler asks for it. Any handler error, timeout or
malformed reply falls back per on_error ('allow' with a visible note, or
'block').
"""

import json
import subprocess

from secure_terminal.sanitize import render_output, sanitize_paste

VERDICTS = ('allow', 'block', 'ask')


def _sanitize_message(text):
    """Advisory text is DISPLAYED, so strip escapes and non-ASCII and cap it."""
    if not text:
        return ''
    return render_output(str(text), 'strip')[:2000]


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


def _error(on_error, why):
    verdict = 'block' if on_error == 'block' else 'allow'
    tail = ' (blocked)' if verdict == 'block' else ' (allowed)'
    return {'verdict': verdict, 'message': why + tail, 'suggestion': '',
            'error': True}


def evaluate(handler_argv, command, timeout=10, on_error='allow',
             cwd='', tab='', transcript_provider=None):
    """Run the handler for `command` and return a decision:
    {'verdict': 'allow'|'block'|'ask', 'message': str, 'suggestion': str,
     'error': bool}. transcript_provider, if given, is called only when the
    handler replies need_transcript."""
    payload = {'version': 1, 'command': command, 'cwd': cwd, 'tab': tab}
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
    return {'verdict': reply['verdict'],
            'message': _sanitize_message(reply.get('message')),
            'suggestion': _sanitize_suggestion(reply.get('suggestion')),
            'error': False}
