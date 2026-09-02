"""Shared output-naming helpers for `navi export`.

One convention for the whole command group: the caller supplies a file *name*
and the writer owns the extension.  Passing 'report', 'report.csv' or
'report.CSV' all resolve to 'report.csv' -- no more double extensions.
"""


def csv_path(name, extension="csv"):
    """Return '<name>.<extension>', stripping a redundant extension if present.

    >>> csv_path("asset_data")
    'asset_data.csv'
    >>> csv_path("asset_data.csv")
    'asset_data.csv'
    """
    stem = str(name)
    suffix = "." + extension
    if stem.lower().endswith(suffix.lower()):
        stem = stem[:-len(suffix)]
    return "{}{}".format(stem, suffix)
