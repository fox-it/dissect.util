from __future__ import annotations

from enum import Enum


class Error(Exception):
    pass


class InvalidLDAPQueryError(Error):
    pass


OPTIMIZER_ATTR_WEIGHTS = {
    "objectGUID": 1,
    "distinguishedName": 1,
    "sAMAccountName": 2,
    "userPrincipalName": 2,
    "mail": 2,
    "sAMAccountType": 3,
    "servicePrincipalName": 3,
    "userAccountControl": 4,
    "memberOf": 5,
    "member": 5,
    "pwdLastSet": 5,
    "primaryGroupID": 6,
    "whenCreated": 6,
    "ou": 6,
    "lastLogonTimestamp": 6,
    "cn": 7,
    "givenName": 7,
    "name": 7,
    "telephoneNumber": 7,
    "objectCategory": 8,
    "description": 9,
    "objectClass": 10,
}


class LdapLogicalOperator(Enum):
    AND = "&"
    OR = "|"
    NOT = "!"


class LdapComparisonOperator(Enum):
    GE = ">="
    LE = "<="
    G = ">"
    L = "<"
    EQ = "="
    APPROX = "~="
    BIT = ":="
    EXTENDED_MATCH = ":"


class LdapSearchFilter:
    """Represents an LDAP search filter (simple or nested)."""

    def __init__(self, query: str) -> None:
        self.query: str = query
        self.children: list[LdapSearchFilter] = []
        self.operator: LdapLogicalOperator | None = None
        self.attribute: str | None = None
        self.comparison_operator: LdapComparisonOperator | None = None
        self.value: str | None = None
        self._extended_rule: str | None = None

        self._validate_syntax(query)

        if query[1:-1].startswith(tuple(op.value for op in LdapLogicalOperator)):
            self._parse_nested(query)
        else:
            self._parse_simple(query)

    def _validate_syntax(self, query: str) -> None:
        """Validate basic LDAP query syntax."""
        if not query:
            raise InvalidLDAPQueryError("Empty query")

        if not query.startswith("(") or not query.endswith(")"):
            raise InvalidLDAPQueryError(f"Query must be wrapped in parentheses: {query}")

        if query.count("(") != query.count(")"):
            raise InvalidLDAPQueryError(f"Unbalanced parentheses in query: {query}")

        # Check for empty parentheses
        if "()" in query:
            raise InvalidLDAPQueryError(f"Empty parentheses found in query: {query}")

        # Check for queries that start with double opening parentheses
        if query.startswith("(("):
            raise InvalidLDAPQueryError(f"Invalid query structure: {query}")

    def _parse_nested(self, query: str) -> None:
        """Parse nested filter."""
        inner = query[1:-1]
        self.operator = LdapLogicalOperator(inner[0])
        index = 1

        while index < len(inner):
            end_index = index + 1
            depth = 1
            while end_index < len(inner) and depth > 0:
                if inner[end_index] == "(":
                    depth += 1
                elif inner[end_index] == ")":
                    depth -= 1
                end_index += 1
            child_query = inner[index:end_index]
            self.children.append(LdapSearchFilter(child_query))
            index = end_index

    def _parse_simple(self, query: str) -> None:
        """Parse simple filter."""
        inner = query[1:-1]

        # Check for extended matching rules first
        if ":" in inner and inner.count(":") >= 2:
            colon_indices = [i for i, c in enumerate(inner) if c == ":"]
            if len(colon_indices) >= 2:
                potential_attr = inner[: colon_indices[0]]
                potential_rule_end = colon_indices[-1]
                if potential_rule_end < len(inner) - 1 and inner[potential_rule_end + 1] == "=":
                    self.attribute = potential_attr
                    rule_part = inner[colon_indices[0] : potential_rule_end + 2]
                    self.comparison_operator = LdapComparisonOperator.EXTENDED_MATCH
                    self.value = inner[potential_rule_end + 2 :]
                    self._extended_rule = rule_part
                    return

        # Regular operator parsing
        test = inner
        operators = []
        sorted_operators = sorted(LdapComparisonOperator, key=lambda op: len(op.value), reverse=True)
        sorted_operators = [op for op in sorted_operators if op != LdapComparisonOperator.EXTENDED_MATCH]

        for operator in sorted_operators:
            if operator.value in test:
                if test.count(operator.value) > 1:
                    raise InvalidLDAPQueryError(
                        f"Comparison operator {operator.value} found multiple times in query: {query}"
                    )
                operators.append(operator)
                test = test.replace(operator.value, "")

        if len(operators) == 0:
            expected_ops = [o.value for o in LdapComparisonOperator if o != LdapComparisonOperator.EXTENDED_MATCH]
            raise InvalidLDAPQueryError(
                f"No comparison operator found in query: {query}. Expected one of {expected_ops}."
            )
        if len(operators) > 1:
            expected_ops = [o.value for o in LdapComparisonOperator if o != LdapComparisonOperator.EXTENDED_MATCH]
            raise InvalidLDAPQueryError(
                f"Multiple comparison operators found in query: {query} -> {[o.value for o in operators]} "
                f"Expected only one of {expected_ops}."
            )

        self.comparison_operator = operators[0]
        self.attribute, _, self.value = inner.partition(self.comparison_operator.value)

    def is_nested(self) -> bool:
        return self.operator is not None

    def format(self) -> str:
        if self.is_nested():
            childs = "".join([child.format() for child in self.children])
            return f"({self.operator.value}{childs})"
        if self.comparison_operator == LdapComparisonOperator.EXTENDED_MATCH:
            return f"({self.attribute}{self._extended_rule}{self.value})"
        return f"({self.attribute}{self.comparison_operator.value}{self.value})"

    def __repr__(self) -> str:
        if self.is_nested():
            return f"LdapSearchFilter(NESTED operator={self.operator}, children={self.children})"
        return (
            f'LdapSearchFilter(attribute="{self.attribute}", operator="{self.comparison_operator.value}", value={self.value})'
        )

    @classmethod
    def parse(cls, query: str, optimize: bool = True) -> LdapSearchFilter:
        """Parse an LDAP query into a filter object, with optional optimization."""
        result = cls(query)
        if optimize:
            return optimize_ldap_query(result)[0]
        return result


def optimize_ldap_query(query: LdapSearchFilter) -> tuple[LdapSearchFilter, int]:
    """
    Optimizes the LDAP query by removing redundant conditions and
    sorting filters and conditions based on how specific they are.
    """
    # Simplify single-child AND/OR
    if (
        query.is_nested()
        and len(query.children) == 1
        and query.operator in (LdapLogicalOperator.AND, LdapLogicalOperator.OR)
    ):
        return optimize_ldap_query(query.children[0])

    # Sort nested children by weight
    if query.is_nested() and len(query.children) > 1:
        new_children = []
        for child in query.children:
            optimized_child, weight = optimize_ldap_query(child)
            new_children.append((weight, optimized_child))

        new_sorted = sorted(new_children, key=lambda x: x[0])
        query.children = [x[1] for x in new_sorted]
        query.query = query.format()
        return query, max(weight for weight, _ in new_sorted)

    # Handle NOT
    if query.is_nested() and len(query.children) == 1 and query.operator == LdapLogicalOperator.NOT:
        optimized_child, weight = optimize_ldap_query(query.children[0])
        query.children[0] = optimized_child
        query.query = query.format()
        return query, weight

    # Base case: simple filter
    if not query.is_nested():
        return query, OPTIMIZER_ATTR_WEIGHTS.get(query.attribute, max(OPTIMIZER_ATTR_WEIGHTS.values()))

    return query, max(OPTIMIZER_ATTR_WEIGHTS.values())
