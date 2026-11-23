"""The pending mark: @pending skips a model-level test until its task removes it.

RUN_PENDING=1 runs marked tests.
"""
import os
import unittest

pending = unittest.skipUnless(os.environ.get("RUN_PENDING") == "1",
                              "pending: set RUN_PENDING=1 to run")
