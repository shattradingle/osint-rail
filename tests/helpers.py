"""Test helpers. One seam: a fake HTTP transport, so nothing here opens a socket."""

from __future__ import annotations

import json
from typing import Any, Callable

Response = tuple[int, bytes, str]
Route = tuple[str, Any]


def text_response(body: str, status: int = 200) -> Response:
    return status, body.encode("utf-8"), "" if status < 400 else f"HTTP {status}"


def json_response(payload: Any, status: int = 200) -> Response:
    return text_response(json.dumps(payload), status)


class FakeTransport:
    """Ordered URL-substring routes plus a default, and a log of what was fetched.

    A route value is either a ``(status, body, error)`` tuple, a two-tuple
    ``(status, body)``, or a callable taking the URL and returning a tuple.
    """

    def __init__(self, routes: list[Route] | None = None, default: Any = None) -> None:
        self.routes: list[Route] = list(routes or [])
        self.default = default if default is not None else text_response("blocked", 403)
        self.calls: list[str] = []

    def __call__(self, url: str, headers: dict[str, str], timeout: float) -> Response:
        self.calls.append(url)
        for fragment, response in self.routes:
            if fragment in url:
                return _normalise(response(url) if callable(response) else response)
        return _normalise(self.default(url) if callable(self.default) else self.default)

    @property
    def count(self) -> int:
        return len(self.calls)


def _normalise(response: Any) -> Response:
    if isinstance(response, tuple):
        if len(response) == 2:
            status, body = response
            return status, body if isinstance(body, bytes) else str(body).encode(), ""
        status, body, error = response
        return status, body if isinstance(body, bytes) else str(body).encode(), error
    raise TypeError(f"bad fake response: {response!r}")


def seq(*responses: Any) -> Callable[[str], Any]:
    """A route that returns each response in turn, then repeats the last one."""
    queue = list(responses)

    def pick(url: str) -> Any:
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return pick


GITHUB_USER = {
    "login": "torvalds",
    "name": "Linus Torvalds",
    "html_url": "https://github.com/torvalds",
    "blog": "https://www.kernel.org",
    "location": "Portland, OR",
    "bio": "kernel",
    "public_repos": 8,
    "followers": 200000,
    "created_at": "2011-09-03T15:26:22Z",
    "avatar_url": "https://avatars.githubusercontent.com/u/1024025",
}

GITHUB_EVENTS = [
    {
        "type": "PushEvent",
        "payload": {
            "commits": [
                {"message": "Merge tag", "author": {"email": "torvalds@linux-foundation.org"}},
                {"message": "noreply", "author": {"email": "1234+torvalds@users.noreply.github.com"}},
            ]
        },
    }
]

GRAVATAR = {
    "entry": [
        {
            "profileUrl": "https://gravatar.com/torvalds",
            "preferredUsername": "torvalds",
            "displayName": "Linus",
            "aboutMe": "kernel maintainer",
            "thumbnailUrl": "https://secure.gravatar.com/avatar/x",
            "name": {"formatted": "Linus Torvalds"},
            "accounts": [
                {"domain": "github.com", "username": "torvalds", "display": "torvalds",
                 "verified": "true", "url": "https://github.com/torvalds"}
            ],
            "urls": [{"value": "https://www.kernel.org"}],
        }
    ]
}

WMN_DATA = {
    "sites": [
        {"name": "Example", "uri_check": "https://example.test/{account}",
         "m_string": "profile for", "cat": "social"},
    ]
}
