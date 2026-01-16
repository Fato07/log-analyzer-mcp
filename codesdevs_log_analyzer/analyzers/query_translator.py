"""Natural language query translator for log analysis.

Translates natural language questions into appropriate tool calls and
combines results to provide meaningful answers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codesdevs_log_analyzer.models import ParsedLogEntry


@dataclass
class QueryIntent:
    """Represents the detected intent from a natural language query."""

    primary_action: str  # search, count, analyze, find_cause, compare, time_range
    focus: str | None = None  # errors, warnings, performance, security, etc.
    time_reference: str | None = None  # "last hour", "today", "between X and Y"
    pattern: str | None = None  # Specific pattern to search for
    context_needed: bool = False  # Whether context lines are needed
    count_requested: bool = False  # Whether a count is requested
    aggregation: str | None = None  # group_by, top_n, etc.
    confidence: float = 0.0  # Confidence score for the intent detection


@dataclass
class QueryResult:
    """Result of a natural language query."""

    question: str
    intent: QueryIntent
    answer: str
    supporting_entries: list[ParsedLogEntry] = field(default_factory=list)
    tool_calls_made: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


class QueryTranslator:
    """Translates natural language questions into log analysis operations."""

    # Question patterns mapped to intents
    QUESTION_PATTERNS: dict[str, dict[str, str | bool | float]] = {
        # "Why" questions - root cause analysis
        r"why\s+(?:did|does|is|was|were|are)": {
            "action": "find_cause",
            "focus": "errors",
            "context_needed": True,
            "confidence": 0.9,
        },
        r"what\s+caused": {
            "action": "find_cause",
            "focus": "errors",
            "context_needed": True,
            "confidence": 0.9,
        },
        r"root\s+cause": {
            "action": "find_cause",
            "focus": "errors",
            "context_needed": True,
            "confidence": 0.95,
        },
        # "When" questions - time-based search
        r"when\s+(?:did|does|was|were)": {
            "action": "time_range",
            "context_needed": False,
            "confidence": 0.85,
        },
        r"what\s+time": {
            "action": "time_range",
            "context_needed": False,
            "confidence": 0.85,
        },
        r"first\s+(?:time|occurrence)": {
            "action": "time_range",
            "aggregation": "first",
            "confidence": 0.9,
        },
        r"last\s+(?:time|occurrence)": {
            "action": "time_range",
            "aggregation": "last",
            "confidence": 0.9,
        },
        # "What happened" questions - summarization
        r"what\s+happened": {
            "action": "analyze",
            "context_needed": True,
            "confidence": 0.85,
        },
        r"summarize|summary|overview": {
            "action": "analyze",
            "context_needed": False,
            "confidence": 0.9,
        },
        # "How many" questions - counting
        r"how\s+many": {
            "action": "count",
            "count_requested": True,
            "confidence": 0.95,
        },
        r"count\s+(?:of|the)": {
            "action": "count",
            "count_requested": True,
            "confidence": 0.9,
        },
        r"number\s+of": {
            "action": "count",
            "count_requested": True,
            "confidence": 0.9,
        },
        # "Find/Show" questions - search
        r"(?:find|show|list|get)\s+(?:all|the)?": {
            "action": "search",
            "context_needed": False,
            "confidence": 0.8,
        },
        r"where\s+(?:is|are|did)": {
            "action": "search",
            "context_needed": True,
            "confidence": 0.8,
        },
        # Comparison questions
        r"compare|difference|diff\s+between": {
            "action": "compare",
            "context_needed": False,
            "confidence": 0.9,
        },
        r"(?:more|less|fewer)\s+(?:errors|warnings|issues)": {
            "action": "compare",
            "count_requested": True,
            "confidence": 0.85,
        },
        # Top/Most questions - aggregation
        r"(?:top|most\s+(?:common|frequent))": {
            "action": "search",
            "aggregation": "top_n",
            "confidence": 0.9,
        },
    }

    # Focus area patterns
    FOCUS_PATTERNS: dict[str, list[str]] = {
        "errors": [
            r"error",
            r"exception",
            r"fail(?:ed|ure|ing)?",
            r"crash(?:ed|ing)?",
            r"broken",
            r"bug",
        ],
        "warnings": [r"warn(?:ing)?", r"deprecated", r"caution"],
        "performance": [
            r"slow",
            r"latency",
            r"timeout",
            r"performance",
            r"response\s+time",
            r"bottleneck",
            r"memory",
            r"cpu",
        ],
        "security": [
            r"security",
            r"auth(?:entication|orization)?",
            r"permission",
            r"access\s+denied",
            r"unauthorized",
            r"forbidden",
            r"attack",
            r"injection",
        ],
        "database": [
            r"database",
            r"db",
            r"sql",
            r"query",
            r"connection\s+pool",
            r"deadlock",
            r"transaction",
        ],
        "network": [
            r"network",
            r"connection",
            r"socket",
            r"http",
            r"api",
            r"request",
            r"response",
            r"timeout",
        ],
        "startup": [
            r"start(?:up|ed|ing)?",
            r"boot",
            r"init(?:ialize|ialization)?",
            r"launch",
        ],
        "shutdown": [
            r"shutdown",
            r"stop(?:ped|ping)?",
            r"terminate",
            r"exit",
            r"graceful",
        ],
    }

    # Time reference patterns
    TIME_PATTERNS: dict[str, str] = {
        r"last\s+(\d+)\s+hour": "last_{0}_hours",
        r"last\s+(\d+)\s+minute": "last_{0}_minutes",
        r"last\s+hour": "last_1_hours",
        r"today": "today",
        r"yesterday": "yesterday",
        r"this\s+morning": "this_morning",
        r"this\s+afternoon": "this_afternoon",
        r"between\s+(\S+)\s+and\s+(\S+)": "between_{0}_and_{1}",
        r"since\s+(\S+)": "since_{0}",
        r"before\s+(\S+)": "before_{0}",
        r"around\s+(\S+)": "around_{0}",
    }

    def __init__(self) -> None:
        """Initialize the query translator."""
        self._compiled_question_patterns: list[
            tuple[re.Pattern[str], dict[str, str | bool | float]]
        ] = [(re.compile(p, re.IGNORECASE), v) for p, v in self.QUESTION_PATTERNS.items()]

        self._compiled_focus_patterns: dict[str, list[re.Pattern[str]]] = {
            focus: [re.compile(p, re.IGNORECASE) for p in patterns]
            for focus, patterns in self.FOCUS_PATTERNS.items()
        }

        self._compiled_time_patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(p, re.IGNORECASE), v) for p, v in self.TIME_PATTERNS.items()
        ]

    def translate(self, question: str) -> QueryIntent:
        """Translate a natural language question into a QueryIntent.

        Args:
            question: The natural language question to translate.

        Returns:
            QueryIntent object representing the detected intent.
        """
        question = question.strip()

        # Detect primary action
        intent = self._detect_action(question)

        # Detect focus area
        intent.focus = self._detect_focus(question)

        # Detect time reference
        intent.time_reference = self._detect_time_reference(question)

        # Extract specific patterns mentioned
        intent.pattern = self._extract_pattern(question)

        return intent

    def _detect_action(self, question: str) -> QueryIntent:
        """Detect the primary action from the question."""
        best_match: QueryIntent | None = None
        best_confidence = 0.0

        for pattern, attrs in self._compiled_question_patterns:
            if pattern.search(question):
                confidence = float(attrs.get("confidence", 0.5))
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = QueryIntent(
                        primary_action=str(attrs.get("action", "search")),
                        context_needed=bool(attrs.get("context_needed", False)),
                        count_requested=bool(attrs.get("count_requested", False)),
                        aggregation=str(attrs["aggregation"])
                        if "aggregation" in attrs
                        else None,
                        confidence=confidence,
                    )

        # Default to search if no pattern matched
        if best_match is None:
            best_match = QueryIntent(
                primary_action="search",
                confidence=0.5,
            )

        return best_match

    def _detect_focus(self, question: str) -> str | None:
        """Detect the focus area from the question."""
        focus_scores: dict[str, int] = {}

        for focus, patterns in self._compiled_focus_patterns.items():
            for pattern in patterns:
                if pattern.search(question):
                    focus_scores[focus] = focus_scores.get(focus, 0) + 1

        if focus_scores:
            # Return the focus with the highest score
            return max(focus_scores, key=lambda k: focus_scores[k])

        return None

    def _detect_time_reference(self, question: str) -> str | None:
        """Detect time references in the question."""
        for pattern, template in self._compiled_time_patterns:
            match = pattern.search(question)
            if match:
                groups = match.groups()
                if groups:
                    return template.format(*groups)
                return template

        return None

    def _extract_pattern(self, question: str) -> str | None:
        """Extract specific search patterns from the question.

        Looks for quoted strings or specific technical terms.
        """
        # Look for quoted strings
        quoted: list[str] = re.findall(r'"([^"]+)"', question)
        if quoted:
            return str(quoted[0])

        quoted = re.findall(r"'([^']+)'", question)
        if quoted:
            return str(quoted[0])

        # Look for specific error codes or identifiers
        # HTTP status codes
        http_codes: list[str] = re.findall(r"\b(4\d{2}|5\d{2})\b", question)
        if http_codes:
            return str(http_codes[0])

        # Error codes like ERR001, E1234
        error_codes: list[str] = re.findall(r"\b([A-Z]{2,5}[-_]?\d{2,6})\b", question)
        if error_codes:
            return str(error_codes[0])

        # Exception class names
        exception_names: list[str] = re.findall(
            r"\b(\w+(?:Error|Exception|Fault))\b", question
        )
        if exception_names:
            return str(exception_names[0])

        return None

    def generate_tool_calls(self, intent: QueryIntent) -> list[str]:
        """Generate the appropriate tool calls based on the intent.

        Args:
            intent: The QueryIntent to translate into tool calls.

        Returns:
            List of tool names to call.
        """
        tools: list[str] = []

        if intent.primary_action == "find_cause":
            tools.extend(
                ["log_analyzer_extract_errors", "log_analyzer_correlate"]
            )
        elif intent.primary_action == "time_range":
            tools.append("log_analyzer_search")
        elif intent.primary_action == "analyze":
            tools.append("log_analyzer_summarize")
            if intent.focus == "errors":
                tools.append("log_analyzer_extract_errors")
        elif intent.primary_action == "count":
            if intent.focus == "errors":
                tools.append("log_analyzer_extract_errors")
            else:
                tools.append("log_analyzer_search")
        elif intent.primary_action == "compare":
            tools.append("log_analyzer_diff")
        elif intent.primary_action == "search":
            if intent.focus == "errors":
                tools.append("log_analyzer_extract_errors")
            else:
                tools.append("log_analyzer_search")

        return tools

    def build_search_pattern(self, intent: QueryIntent) -> str | None:
        """Build a search pattern based on the intent.

        Args:
            intent: The QueryIntent to build a pattern from.

        Returns:
            A regex pattern string or None.
        """
        if intent.pattern:
            return intent.pattern

        if intent.focus:
            focus_patterns = self.FOCUS_PATTERNS.get(intent.focus, [])
            if focus_patterns:
                # Create an OR pattern from focus keywords
                return "|".join(f"(?:{p})" for p in focus_patterns)

        return None

    def format_answer(
        self,
        intent: QueryIntent,
        results: dict[str, object],
        entries: list[ParsedLogEntry],
    ) -> str:
        """Format the results into a natural language answer.

        Args:
            intent: The original query intent.
            results: Results from tool calls.
            entries: Supporting log entries.

        Returns:
            A formatted answer string.
        """
        if intent.primary_action == "count":
            count = len(entries)
            focus_label = intent.focus or "entries"
            return f"Found **{count}** {focus_label} in the log file."

        if intent.primary_action == "find_cause":
            if not entries:
                return (
                    "No errors found that match your query. "
                    "Try broadening your search criteria."
                )

            # Build a root cause explanation
            answer_parts = [f"Found **{len(entries)}** related entries.\n"]

            if "causal_chain" in results:
                chain = results["causal_chain"]
                if isinstance(chain, dict) and chain.get("hypothesis"):
                    answer_parts.append(
                        f"\n**Root Cause Analysis:**\n{chain['hypothesis']}"
                    )

            if "recommendations" in results:
                recs = results["recommendations"]
                if isinstance(recs, list) and recs:
                    answer_parts.append("\n**Recommendations:**")
                    for rec in recs[:5]:
                        answer_parts.append(f"- {rec}")

            return "\n".join(answer_parts)

        if intent.primary_action == "analyze":
            summary = results.get("summary", "")
            if summary:
                return str(summary)
            return "Analysis complete. See the supporting entries for details."

        if intent.primary_action == "time_range":
            if not entries:
                return "No entries found matching the time criteria."

            first_entry = entries[0]
            last_entry = entries[-1]
            first_time = getattr(first_entry, "timestamp", "unknown")
            last_time = getattr(last_entry, "timestamp", "unknown")

            return (
                f"Found **{len(entries)}** entries.\n"
                f"- First occurrence: {first_time}\n"
                f"- Last occurrence: {last_time}"
            )

        # Default search response
        if not entries:
            return "No matching entries found."

        return f"Found **{len(entries)}** matching entries."

    def suggest_followup(self, intent: QueryIntent) -> list[str]:
        """Generate follow-up question suggestions.

        Args:
            intent: The original query intent.

        Returns:
            List of suggested follow-up questions.
        """
        suggestions: list[str] = []

        if intent.primary_action == "search":
            suggestions.append("What caused these errors?")
            suggestions.append("How many times did this occur?")
            suggestions.append("When did this first happen?")

        elif intent.primary_action == "find_cause":
            suggestions.append("Show me similar errors in the past hour")
            suggestions.append("Are there any warnings before these errors?")

        elif intent.primary_action == "count":
            suggestions.append("Show me the actual entries")
            suggestions.append("What are the most common error types?")

        elif intent.primary_action == "analyze":
            suggestions.append("What errors occurred?")
            suggestions.append("Were there any performance issues?")

        return suggestions[:3]  # Return top 3 suggestions
