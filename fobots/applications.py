# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Applications `fobots init --application NAME` knows: where their web server configuration
is, and what to write in fobots.conf for them. To support another one, add an entry here."""
import os

APPLICATIONS = {
    "gitlab": {
        "title": "GitLab Omnibus",
        # its own nginx, not /etc/nginx
        "nginx_confs": ("/var/opt/gitlab/nginx/conf/nginx.conf",),
        # present: init suggests the option
        "detect": ("/var/opt/gitlab/nginx/conf/nginx.conf",),
        # a page loads ~25 of them (webpack, CSS, fonts, icons, avatars): counted, two pages
        # in a row put a visitor above the threshold. They cost almost nothing to serve.
        "ignore_path": r"^/(assets/|uploads/-/system/|favicon)",
        "ignore_comment": "static files of GitLab (webpack, CSS, fonts, icons, avatars, logos): "
                          "a page loads ~25 of them",
    },
}


def detected():
    """Names of the applications whose files are present on this machine."""
    return [name for name, app in APPLICATIONS.items()
            if any(os.path.exists(p) for p in app.get("detect", ()))]
