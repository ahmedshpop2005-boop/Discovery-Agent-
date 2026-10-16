"""AutoPentest Sentinel - evidence-first agentic security assessment platform.

The package is organised into small, single-purpose layers:

* ``app.safety``    - authorization guard, target validation, redaction.
* ``app.models``    - typed Pydantic records (findings, evidence).
* ``app.tools``     - real, non-destructive collection tools + registry.
* ``app.agents``    - LangGraph planner/executor/validator workflow.
* ``app.knowledge`` - local remediation retrieval.
* ``app.reporting`` - PDF report generation.
* ``app.api``       - HTTP interface.

Layer rule: tools never know about the HTTP layer, and the agent never calls
a subprocess directly - it only dispatches registered tools.
"""

__version__ = "2.0.0"
