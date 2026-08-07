"""The `loglens-ui` command.

Deliberately its own module and deliberately free of any Streamlit import at
the top level. `ui.py` cannot be that, because `@st.cache_data` is applied at
import time and so needs the real library present. Pointing the console script
at `ui.py` therefore meant that on an install without the `ui` extra the
command died with an ImportError traceback before it could explain itself.

The person running it has almost certainly just not installed the extra, and a
traceback is a poor way to say so.
"""

from __future__ import annotations

import os
import sys

# Where `ui.py` looks for the files to prefill. Duplicated as a literal rather
# than imported, since importing `ui` is exactly what this module must not do.
PATHS_ENV = "LOGLENS_UI_PATHS"

MISSING = """\
The browser view needs Streamlit, which is an optional extra:

    pip install "loglens[ui]"

The terminal report needs nothing beyond Python:

    loglens report {example}
"""


def main() -> int:
    paths = sys.argv[1:]

    try:
        from streamlit.web import cli as stcli
    except ImportError:
        print(MISSING.format(example=paths[0] if paths else "app.log"), file=sys.stderr)
        return 1

    if paths:
        os.environ[PATHS_ENV] = " ".join(paths)

    app = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.py")
    sys.argv = ["streamlit", "run", app]
    return stcli.main()


if __name__ == "__main__":
    raise SystemExit(main())
