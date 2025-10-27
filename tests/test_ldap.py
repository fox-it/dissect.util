from __future__ import annotations

import pytest

from dissect.util.ldap import (
    OPTIMIZER_ATTR_WEIGHTS,
    ComparisonOperator,
    InvalidQueryError,
    LogicalOperator,
    SearchFilter,
    optimize_ldap_query,
)


@pytest.mark.parametrize(
    ("query", "match"),
    [
        ("(&(objectClass=user)(name=Henk)))", "Unbalanced parentheses"),
        ("(objectClass=user)(name=Henk)", "Comparison operator = found multiple times in query"),
        ("", "Empty query"),
        ("name=test", "Query must be wrapped in parentheses"),
        ("()", "Empty parentheses found"),
        ("((test))", "Invalid query structure"),
    ],
)
def test_invalid_query(query: str, match: str) -> None:
    """Test against various invalid LDAP queries."""
    with pytest.raises(InvalidQueryError, match=match):
        SearchFilter.parse(query)


@pytest.mark.parametrize(
    ("query", "attribute", "value"),
    [
        ("(name=Henk*)", "name", "Henk*"),
        ("(name=*son)", "name", "*son"),
        ("(givenName=*Jan*)", "givenName", "*Jan*"),
        ("(mail=*@*.com)", "mail", "*@*.com"),
    ],
)
def test_wildcards(query: str, attribute: str, value: str) -> None:
    """Test wildcard support in various positions."""
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.attribute == attribute
    assert parsed.value == value


def test_wildcards_nested() -> None:
    """Test wildcards in nested filters."""
    query = "(&(objectClass=user)(name=*Henk*))"
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.children[1].attribute == "name"
    assert parsed.children[1].value == "*Henk*"


def test_parsing_and_no_optimization() -> None:
    """Test parsing without optimization."""
    query = "(&(objectClass=user)(|(name=Henk)(name=Jan)))"
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.query == query, "Query was optimized"

    assert len(parsed.children) == 2
    assert parsed.operator == LogicalOperator.AND
    assert isinstance(parsed.children[0], SearchFilter)
    assert parsed.children[0].attribute == "objectClass"
    assert parsed.children[0].value == "user"
    assert parsed.children[0].operator.value == "="

    assert isinstance(parsed.children[1], SearchFilter)
    assert parsed.children[1].operator == LogicalOperator.OR
    assert parsed.children[1].query == "(|(name=Henk)(name=Jan))"
    assert parsed.children[1].children[0].attribute == "name"
    assert parsed.children[1].children[0].operator.value == "="
    assert parsed.children[1].children[0].value == "Henk"
    assert parsed.children[1].children[1].attribute == "name"
    assert parsed.children[1].children[1].operator.value == "="
    assert parsed.children[1].children[1].value == "Jan"


def test_parsing_and_suboptimal() -> None:
    """Test parsing with optimization."""
    query = "(&(objectClass=user)(|(name=Henk)(name=Jan)))"
    parsed = SearchFilter.parse(query)
    assert parsed.query != query, "Query was not optimized"

    assert len(parsed.children) == 2
    assert parsed.operator == LogicalOperator.AND
    assert isinstance(parsed.children[1], SearchFilter)
    assert parsed.children[1].attribute == "objectClass"
    assert parsed.children[1].operator.value == "="
    assert parsed.children[1].value == "user"

    assert isinstance(parsed.children[0], SearchFilter)
    assert parsed.children[0].operator == LogicalOperator.OR
    assert parsed.children[0].query == "(|(name=Henk)(name=Jan))"
    assert parsed.children[0].children[0].attribute == "name"
    assert parsed.children[0].children[0].operator.value == "="
    assert parsed.children[0].children[0].value == "Henk"
    assert parsed.children[0].children[1].attribute == "name"
    assert parsed.children[0].children[1].operator.value == "="
    assert parsed.children[0].children[1].value == "Jan"


def test_parsing_or() -> None:
    """Test parsing OR filters."""
    query = "(|(name=Henk)(name=Jan))"
    parsed = SearchFilter.parse(query)
    assert parsed.query == query, "Query was optimized"

    assert len(parsed.children) == 2
    assert parsed.operator == LogicalOperator.OR
    assert isinstance(parsed.children[0], SearchFilter)
    assert parsed.children[0].attribute == "name"
    assert parsed.children[0].operator.value == "="
    assert parsed.children[0].value == "Henk"
    assert isinstance(parsed.children[1], SearchFilter)
    assert parsed.children[1].attribute == "name"
    assert parsed.children[1].operator.value == "="
    assert parsed.children[1].value == "Jan"


def test_parsing_or_2() -> None:
    """Test parsing OR filters with AND parent."""
    query = "(&(|(name=Henk)(name=Jan))(surname=de Vries))"
    parsed = SearchFilter.parse(query)
    assert parsed.query == query, "Query was optimized"

    assert len(parsed.children) == 2
    assert parsed.operator == LogicalOperator.AND
    assert isinstance(parsed.children[0], SearchFilter)
    assert parsed.children[0].query == "(|(name=Henk)(name=Jan))"
    assert len(parsed.children[0].children) == 2
    assert isinstance(parsed.children[0].children[0], SearchFilter)
    assert parsed.children[0].operator == LogicalOperator.OR
    assert parsed.children[0].children[0].attribute == "name"
    assert parsed.children[0].children[0].operator.value == "="
    assert parsed.children[0].children[0].value == "Henk"
    assert isinstance(parsed.children[0].children[1], SearchFilter)
    assert parsed.children[0].children[1].attribute == "name"
    assert parsed.children[0].children[1].operator.value == "="
    assert parsed.children[0].children[1].value == "Jan"
    assert isinstance(parsed.children[1], SearchFilter)
    assert parsed.children[1].attribute == "surname"
    assert parsed.children[1].operator.value == "="
    assert parsed.children[1].value == "de Vries"


def test_parsing_nested_and_or() -> None:
    """Test parsing nested AND/OR filters."""
    query = (
        "(|(objectClass=container)(objectClass=organizationalUnit)"
        "(sAMAccountType>=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
    )
    parsed = SearchFilter.parse(query)
    assert parsed.query != query, "Query was not optimized"

    assert len(parsed.children) == 5

    assert isinstance(parsed.children[0], SearchFilter)
    assert parsed.children[0].query == "(sAMAccountType>=805306369)"
    assert parsed.children[0].attribute == "sAMAccountType"
    assert parsed.children[0].operator.value == ">="
    assert parsed.children[0].value == "805306369"

    assert isinstance(parsed.children[2], SearchFilter)
    assert parsed.children[2].query == "(objectClass=organizationalUnit)"
    assert parsed.children[2].attribute == "objectClass"
    assert parsed.children[2].operator.value == "="
    assert parsed.children[2].value == "organizationalUnit"

    assert isinstance(parsed.children[1], SearchFilter)
    assert parsed.children[1].query == "(objectClass=container)"
    assert parsed.children[1].attribute == "objectClass"
    assert parsed.children[1].operator.value == "="
    assert parsed.children[1].value == "container"

    assert isinstance(parsed.children[3], SearchFilter)
    assert parsed.children[3].query == "(objectClass=group)"
    assert parsed.children[3].attribute == "objectClass"
    assert parsed.children[3].operator.value == "="
    assert parsed.children[3].value == "group"

    assert isinstance(parsed.children[4], SearchFilter)
    assert parsed.children[4].query == "(&(objectCategory=person)(objectClass=user))"
    assert parsed.children[4].operator == LogicalOperator.AND
    assert len(parsed.children[4].children) == 2
    assert isinstance(parsed.children[4].children[0], SearchFilter)
    assert parsed.children[4].children[0].query == "(objectCategory=person)"
    assert parsed.children[4].children[0].attribute == "objectCategory"
    assert parsed.children[4].children[0].operator.value == "="
    assert parsed.children[4].children[0].value == "person"
    assert isinstance(parsed.children[4].children[1], SearchFilter)
    assert parsed.children[4].children[1].query == "(objectClass=user)"
    assert parsed.children[4].children[1].attribute == "objectClass"
    assert parsed.children[4].children[1].operator.value == "="
    assert parsed.children[4].children[1].value == "user"


def test_parsing_single_not() -> None:
    """Test parsing single NOT filter."""
    query = "(!(sAMAccountType=805306369))"
    parsed = SearchFilter.parse(query)
    assert parsed.query == query, "Query was optimized"

    assert len(parsed.children) == 1
    assert parsed.operator == LogicalOperator.NOT
    assert isinstance(parsed.children[0], SearchFilter)
    assert parsed.children[0].attribute == "sAMAccountType"
    assert parsed.children[0].operator.value == "="
    assert parsed.children[0].value == "805306369"


def test_parsing_single_filter_in_condition() -> None:
    """Test parsing single filter in AND condition."""
    query = "(&(objectClass=user))"
    parsed = SearchFilter.parse(query)
    assert parsed.query != query, "Query was not optimized"

    assert parsed.query == "(objectClass=user)"


@pytest.mark.parametrize(
    ("query", "attribute", "operator", "value"),
    [
        pytest.param("(age>=18)", "age", ComparisonOperator.GE, "18", id=">="),
        pytest.param("(age<=30)", "age", ComparisonOperator.LE, "30", id="<="),
        pytest.param("(priority>5)", "priority", ComparisonOperator.GT, "5", id=">"),
        pytest.param("(score<100)", "score", ComparisonOperator.LT, "100", id="<"),
        pytest.param("(name=Henk)", "name", ComparisonOperator.EQ, "Henk", id="="),
        pytest.param("(name~=Henk)", "name", ComparisonOperator.APPROX, "Henk", id="~="),
        pytest.param("(userAccountControl:=2)", "userAccountControl", ComparisonOperator.BIT, "2", id=":="),
    ],
)
def test_comparison_operators(query: str, attribute: str, operator: ComparisonOperator, value: str) -> None:
    """Test various comparison operators."""
    parsed = SearchFilter.parse(query, optimize=False)

    assert not parsed.is_nested()
    assert parsed.attribute == attribute
    assert parsed.operator == operator
    assert parsed.value == value


def test_all_comparison_operators_in_nested_filter() -> None:
    """Test all comparison operators in nested filter."""
    query = "(&(name=Henk)(age>=18)(score<=100)(priority>5)(weight<75)(description~=admin)(flags:=1024))"
    parsed = SearchFilter.parse(query, optimize=False)

    assert parsed.is_nested()
    assert parsed.operator == LogicalOperator.AND
    assert len(parsed.children) == 7

    # name = Henk
    assert parsed.children[0].attribute == "name"
    assert parsed.children[0].operator.value == "="
    assert parsed.children[0].value == "Henk"

    # age >= 18
    assert parsed.children[1].attribute == "age"
    assert parsed.children[1].operator.value == ">="
    assert parsed.children[1].value == "18"

    # score <= 100
    assert parsed.children[2].attribute == "score"
    assert parsed.children[2].operator.value == "<="
    assert parsed.children[2].value == "100"

    # priority > 5
    assert parsed.children[3].attribute == "priority"
    assert parsed.children[3].operator.value == ">"
    assert parsed.children[3].value == "5"

    # weight < 75
    assert parsed.children[4].attribute == "weight"
    assert parsed.children[4].operator.value == "<"
    assert parsed.children[4].value == "75"

    # description ~= admin
    assert parsed.children[5].attribute == "description"
    assert parsed.children[5].operator.value == "~="
    assert parsed.children[5].value == "admin"

    # flags := 1024
    assert parsed.children[6].attribute == "flags"
    assert parsed.children[6].operator.value == ":="
    assert parsed.children[6].value == "1024"


def test_nested_not_with_different_comparison_operators() -> None:
    """Test NOT with various comparison operators."""
    query = "(!(|(age<18)(score>=90)(userAccountControl:=512)))"
    parsed = SearchFilter.parse(query, optimize=False)

    assert parsed.is_nested()
    assert parsed.operator == LogicalOperator.NOT
    assert len(parsed.children) == 1

    # Inner OR filter
    inner_filter = parsed.children[0]
    assert inner_filter.operator == LogicalOperator.OR
    assert len(inner_filter.children) == 3

    # age < 18
    assert inner_filter.children[0].attribute == "age"
    assert inner_filter.children[0].operator.value == "<"
    assert inner_filter.children[0].value == "18"

    # score >= 90
    assert inner_filter.children[1].attribute == "score"
    assert inner_filter.children[1].operator.value == ">="
    assert inner_filter.children[1].value == "90"

    # userAccountControl := 512
    assert inner_filter.children[2].attribute == "userAccountControl"
    assert inner_filter.children[2].operator.value == ":="
    assert inner_filter.children[2].value == "512"


def test_complex_nested_with_all_operators() -> None:
    """Test complex nested filters with multiple operators."""
    query = "(&(objectClass=person)(!(department~=temp))(|(age>=21)(|(salary>9000)(title<=manager))))"
    parsed = SearchFilter.parse(query, optimize=False)

    assert parsed.is_nested()
    assert parsed.operator == LogicalOperator.AND
    assert len(parsed.children) == 3

    # First: (objectClass=person)
    assert parsed.children[0].attribute == "objectClass"
    assert parsed.children[0].operator.value == "="
    assert parsed.children[0].value == "person"

    # Second: (!(department~=temp))
    not_filter = parsed.children[1]
    assert not_filter.operator == LogicalOperator.NOT
    assert not_filter.children[0].attribute == "department"
    assert not_filter.children[0].operator.value == "~="
    assert not_filter.children[0].value == "temp"

    # Third: (|(age>=21)(|(salary>50000)(title<=manager)))
    or_filter = parsed.children[2]
    assert or_filter.operator == LogicalOperator.OR
    assert len(or_filter.children) == 2

    # age >= 21
    assert or_filter.children[0].attribute == "age"
    assert or_filter.children[0].operator.value == ">="
    assert or_filter.children[0].value == "21"

    # Inner OR: (|(salary>50000)(title<=manager))
    inner_or = or_filter.children[1]
    assert inner_or.operator == LogicalOperator.OR
    assert len(inner_or.children) == 2

    # salary > 50000
    assert inner_or.children[0].attribute == "salary"
    assert inner_or.children[0].operator.value == ">"
    assert inner_or.children[0].value == "9000"

    # title <= manager (this tests string values with comparison operators)
    assert inner_or.children[1].attribute == "title"
    assert inner_or.children[1].operator.value == "<="
    assert inner_or.children[1].value == "manager"


def test_presence_filters() -> None:
    """Test presence filters."""
    # Presence filter - attribute exists
    query = "(mailNickName=*)"
    parsed = SearchFilter.parse(query, optimize=False)

    assert not parsed.is_nested()
    assert parsed.attribute == "mailNickName"
    assert parsed.operator.value == "="
    assert parsed.value == "*"


def test_absence_filters() -> None:
    """Test absence filters."""
    # Absence filter - attribute does not exist
    query = "(!(proxyAddresses=*))"
    parsed = SearchFilter.parse(query, optimize=False)

    assert parsed.is_nested()
    assert parsed.operator == LogicalOperator.NOT
    assert len(parsed.children) == 1

    inner = parsed.children[0]
    assert inner.attribute == "proxyAddresses"
    assert inner.operator.value == "="
    assert inner.value == "*"


@pytest.mark.parametrize(
    ("query", "attribute", "value"),
    [
        ("(name=Henk*)", "name", "Henk*"),
        ("(name=*Henk)", "name", "*Henk"),
        ("(name=*Jo*hn*)", "name", "*Jo*hn*"),
        ("(email=*@domain.com)", "email", "*@domain.com"),
    ],
)
def test_wildcard_with_different_operators(query: str, attribute: str, value: str) -> None:
    """Test wildcards with = operator. Wildcards should work with = operator in all positions."""
    parsed = SearchFilter.parse(query, optimize=False)

    assert not parsed.is_nested()
    assert parsed.attribute == attribute
    assert parsed.operator.value == "="
    assert parsed.value == value


@pytest.mark.parametrize(
    ("expected", "attribute", "op", "value"),
    [
        pytest.param("(name=value)", "name", "=", "value", id="="),
        pytest.param("(age>=18)", "age", ">=", "18", id=">="),
        pytest.param("(score<=100)", "score", "<=", "100", id="<="),
        pytest.param("(priority>5)", "priority", ">", "5", id=">"),
        pytest.param("(weight<75)", "weight", "<", "75", id="<"),
        pytest.param("(desc~=admin)", "desc", "~=", "admin", id="!="),
        pytest.param("(flags:=1024)", "flags", ":=", "1024", id=":="),
    ],
)
def test_format_with_all_operators(expected: str, attribute: str, op: str, value: str) -> None:
    """Test format() method with all operators."""
    query = f"({attribute}{op}{value})"
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.format() == expected, f"Failed for {query}"


def test_error_no_comparison_operator() -> None:
    """Test error for missing comparison operator."""
    with pytest.raises(InvalidQueryError, match="No comparison operator found in query: .+ Expected one of .*"):
        SearchFilter.parse("(attributename)", optimize=False)


def test_error_multiple_comparison_operators() -> None:
    """Test error for multiple comparison operators."""
    # This creates a query with both >= and <= operators
    with pytest.raises(InvalidQueryError, match="Multiple comparison operators found"):
        SearchFilter.parse("(attribute>=value<=other)", optimize=False)


def test_repr_nested_filter() -> None:
    """Test ``__repr__`` for nested filters."""
    query = "(&(name=Henk)(age>=18))"
    parsed = SearchFilter.parse(query, optimize=False)

    # Test repr of the main nested filter
    assert (
        repr(parsed)
        == "<SearchFilter nested operator='&' children=[<SearchFilter attribute='name' operator='=' value=Henk>, <SearchFilter attribute='age' operator='>=' value=18>]>"  # noqa: E501
    )


def test_repr_simple_filter() -> None:
    """Test ``__repr__`` for simple filters."""
    query = "(name=Henk)"
    parsed = SearchFilter.parse(query, optimize=False)

    assert repr(parsed) == "<SearchFilter attribute='name' operator='=' value=Henk>"


def test_optimizer_fallback_case() -> None:
    """Test optimizer fallback case."""
    # Create a nested filter that doesn't match other optimization cases

    obj = SearchFilter.__new__(SearchFilter)
    obj.query = "(&)"
    obj.children = []
    obj.operator = LogicalOperator.AND
    obj.attribute = None
    obj.value = None

    # This should hit the fallback case
    _, weight = optimize_ldap_query(obj)
    assert weight == max(OPTIMIZER_ATTR_WEIGHTS.values())


def test_extended_matching_rules() -> None:
    """Test extended matching rules."""
    # BIT_AND rule (1.2.840.113556.1.4.803)
    query = "(groupType:1.2.840.113556.1.4.803:=8)"
    parsed = SearchFilter.parse(query, optimize=False)

    assert not parsed.is_nested()
    assert parsed.attribute == "groupType"
    assert parsed.operator == ComparisonOperator.EXTENDED
    assert parsed.value == "8"
    assert parsed._extended_rule == "1.2.840.113556.1.4.803"

    # Test formatting of extended matching rules
    assert parsed.format() == query

    # BIT_OR rule (1.2.840.113556.1.4.804)
    query = "(userAccountControl:1.2.840.113556.1.4.804:=65568)"
    parsed = SearchFilter.parse(query, optimize=False)

    assert not parsed.is_nested()
    assert parsed.attribute == "userAccountControl"
    assert parsed.operator == ComparisonOperator.EXTENDED
    assert parsed.value == "65568"
    assert parsed._extended_rule == "1.2.840.113556.1.4.804"

    # Test formatting of extended matching rules
    assert parsed.format() == query


def test_extended_matching_in_nested_query() -> None:
    """Test extended matching in nested queries."""
    query = "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))"
    parsed = SearchFilter.parse(query, optimize=False)

    assert parsed.is_nested()
    assert parsed.operator == LogicalOperator.AND
    assert len(parsed.children) == 2

    # First child - regular filter
    assert parsed.children[0].attribute == "objectClass"
    assert parsed.children[0].operator.value == "="
    assert parsed.children[0].value == "group"

    # Second child - extended matching rule
    assert parsed.children[1].attribute == "groupType"
    assert parsed.children[1].operator == ComparisonOperator.EXTENDED
    assert parsed.children[1].value == "2147483648"
    assert parsed.children[1]._extended_rule == "1.2.840.113556.1.4.803"


def test_not_operator_optimization() -> None:
    """Test that NOT operators properly optimize their children."""
    # Create a NOT filter with a redundant single-child AND that should be optimized
    query = "(!(&(objectClass=user)))"

    # Parse with optimization enabled
    parsed_optimized = SearchFilter.parse(query, optimize=True)

    # Parse without optimization to compare
    parsed_unoptimized = SearchFilter.parse(query, optimize=False)

    # The optimized version should have simplified the inner (&(objectClass=user)) to just (objectClass=user)
    assert parsed_optimized.operator == LogicalOperator.NOT
    assert len(parsed_optimized.children) == 1

    # The child should be a simple filter (not nested) after optimization
    inner_child = parsed_optimized.children[0]
    assert not inner_child.is_nested()
    assert inner_child.attribute == "objectClass"
    assert inner_child.value == "user"

    # Verify the query strings are different (optimization occurred)
    assert parsed_optimized.query != parsed_unoptimized.query
    assert parsed_optimized.query == "(!(objectClass=user))"

    # Test with a more complex case: NOT with nested AND containing OR
    complex_query = "(!(&(|(name=Henk)(name=Jan))))"
    complex_parsed = SearchFilter.parse(complex_query, optimize=True)

    # Should optimize to: (!(|(name=Henk)(name=Jan)))
    assert complex_parsed.operator == LogicalOperator.NOT
    inner = complex_parsed.children[0]
    assert inner.operator == LogicalOperator.OR
    assert len(inner.children) == 2
    assert complex_parsed.query == "(!(|(name=Henk)(name=Jan)))"


def test_real_world_examples() -> None:
    """Test real-world LDAP filter examples."""
    query1 = "(&(objectclass=user)(displayName=Henk))"
    parsed = SearchFilter.parse(query1, optimize=False)
    assert parsed.operator == LogicalOperator.AND
    assert len(parsed.children) == 2

    query2 = "(!(objectClass=group))"
    parsed = SearchFilter.parse(query2, optimize=False)
    assert parsed.operator == LogicalOperator.NOT
    assert parsed.children[0].attribute == "objectClass"
    assert parsed.children[0].value == "group"

    query = "(mail=*@henk.nl)"
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.attribute == "mail"
    assert parsed.value == "*@henk.nl"

    query = "(mdbStorageQuota>=100000)"
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.attribute == "mdbStorageQuota"
    assert parsed.operator.value == ">="
    assert parsed.value == "100000"

    query = "(displayName~=Henk)"
    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.attribute == "displayName"
    assert parsed.operator.value == "~="
    assert parsed.value == "Henk"


def test_anr_style_filters() -> None:
    """Test ANR-style filters."""
    # Simple ANR-style filter (though ANR itself is server-side)
    query1 = "(anr=Henk)"
    parsed = SearchFilter.parse(query1, optimize=False)
    assert parsed.attribute == "anr"
    assert parsed.value == "Henk"

    # ANR with partial match
    query2 = "(anr=Henk*)"
    parsed = SearchFilter.parse(query2, optimize=False)
    assert parsed.attribute == "anr"
    assert parsed.value == "Henk*"


def test_complex_real_world_filter() -> None:
    """Test complex real-world filter."""
    # Complex filter for finding specific user accounts
    query = (
        "(&"
        "(objectClass=user)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(|(sAMAccountName=admin*)(mail=*@admin.*))"
        "(pwdLastSet>=0)"
        "(!(description=*))"
        ")"
    )

    parsed = SearchFilter.parse(query, optimize=False)
    assert parsed.operator == LogicalOperator.AND
    assert len(parsed.children) == 5

    # Check that all components are parsed correctly
    # objectClass=user
    assert any(child.attribute == "objectClass" and child.value == "user" for child in parsed.children)

    # Extended matching rule for userAccountControl
    bit_filter = next(
        (
            child
            for child in parsed.children
            if child.operator == LogicalOperator.NOT and child.children[0].operator == ComparisonOperator.EXTENDED
        ),
        None,
    )
    assert bit_filter is not None
    assert bit_filter.children[0].attribute == "userAccountControl"

    # OR condition with wildcards
    or_filter = next((child for child in parsed.children if child.operator == LogicalOperator.OR), None)
    assert or_filter is not None
    assert len(or_filter.children) == 2
    assert "admin*" in [child.value for child in or_filter.children]
    assert "*@admin.*" in [child.value for child in or_filter.children]
