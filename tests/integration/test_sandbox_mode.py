"""
Integration tests for sandbox mode.

Build Order: Step 13

MUST PASS:
  #3 — Evil server sandbox: exfil detected
  #4 — Evil server sandbox: canary leaked
  #5 — Evil server sandbox: /tmp write detected
"""

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]

# TODO: Step 13 — test_evil_server_exfil_detected (MUST PASS #3)
# TODO: Step 13 — test_evil_server_canary_leaked (MUST PASS #4)
# TODO: Step 13 — test_evil_server_tmp_write_detected (MUST PASS #5)
