"""Output-encoding helpers for embedding untrusted data into HTML.

There are two distinct sinks in the HTML exporters, each with its own rule.
Keeping each rule as a single named operation means a new exporter picks up
the correct encoding by calling one function, instead of re-deriving (or
forgetting) the escaping at every JSON-into-``<script>`` boundary.

``json_for_script``
    Serialize a Python object to JSON destined for an *inline* ``<script>``
    element.  ``json.dumps`` neutralizes quotes and backslashes but not ``/``,
    ``<`` or ``>``.  The HTML tokenizer matches ``</script>`` regardless of
    JavaScript string context, so a device-supplied ``</script>`` inside any
    JSON string value would close the element early and turn the rest of the
    payload into live DOM.  We neutralize ``<``, ``>`` and ``&`` as their
    ``\\uXXXX`` escapes.  This is valid inside a JSON string (and JSON only
    ever emits those characters inside string values, never as structure), so
    the result stays valid JSON/JavaScript while ``</script>``, ``<!--`` and
    ``-->`` can no longer appear literally.  Same rule as Django's
    ``json_script`` / the OWASP JSON-in-HTML guidance.

``escape_html``
    Escape device text destined for an HTML element or attribute value (e.g.
    ``<title>`` or a sidebar ``<strong>``).  This is the ordinary
    ``&<>"'`` sink, handled by the standard library.
"""

from __future__ import annotations

import html as _html
import json
from typing import Any

# ``<``, ``>`` and ``&`` -> their JSON/JS ``\uXXXX`` escapes.  Neutralizes
# ``</script>``, ``<!--`` and ``-->`` in one pass without altering meaning.
_SCRIPT_ESCAPES = {
    ord("<"): "\\u003c",
    ord(">"): "\\u003e",
    ord("&"): "\\u0026",
}


def json_for_script(obj: Any, **dumps_kwargs: Any) -> str:
    """Serialize *obj* to JSON safe to interpolate into an inline ``<script>``.

    Accepts the same keyword arguments as :func:`json.dumps`.
    """
    return json.dumps(obj, **dumps_kwargs).translate(_SCRIPT_ESCAPES)


def escape_html(text: Any) -> str:
    """HTML-escape *text* for an element or attribute-value sink."""
    return _html.escape(str(text))
