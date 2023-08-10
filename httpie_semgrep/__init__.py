import os
import sys

from httpie.plugins import AuthPlugin
from httpie.status import ExitStatus
from requests.auth import AuthBase
from yaml import safe_load


class SemgrepAuth(AuthBase):
    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return self.token == getattr(other, "token", None)

    def __call__(self, r):
        r.headers["Authorization"] = f"Bearer {self.token}"
        return r


class SemgrepAuthPlugin(AuthPlugin):
    name = "Semgrep Auth"
    auth_type = "semgrep"
    description = ""
    auth_require = False

    def get_auth(self, username=None, password=None):
        config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~")
        settings_filename = os.path.join(config_home, ".semgrep/settings.yml")
        try:
            with open(settings_filename) as fp:
                settings = safe_load(fp)
        except OSError:
            sys.stderr.write(
                f"httpie-semgrep error: failed to load {settings_filename!r}. Are you logged in?\n"
            )
            sys.exit(ExitStatus.PLUGIN_ERROR)

        token = settings.get("api_token")

        if not token:
            sys.stderr.write(
                f"httpie-semgrep error: api_token not found in {settings_filename!r}. Are you logged in?\n"
            )
            sys.exit(ExitStatus.PLUGIN_ERROR)

        return SemgrepAuth(token)


def main():
    import httpie.__main__

    sys.argv = sys.argv[:1] + ["--auth-type", "semgrep"] + sys.argv[1:]
    sys.exit(httpie.__main__.main())
