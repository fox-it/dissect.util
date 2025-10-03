from __future__ import annotations

import pytest

from dissect.util.ldap import (
    OPTIMIZER_ATTR_WEIGHTS,
    InvalidLDAPQueryError,
    LdapComparisonOperator,
    LdapSearchFilter,
    LdapLogicalOperator,
    optimize_ldap_query,
)


def test_wrong_query_extra_parenthesis() -> None:
    query = "(&(objectClass=user)(name=Henk)))"
    pytest.raises(InvalidLDAPQueryError, LdapSearchFilter.parse, query)


def test_wrong_query_no_operator() -> None:
    query = "(objectClass=user)(name=Henk)"
    pytest.raises(InvalidLDAPQueryError, LdapSearchFilter.parse, query)


def test_validation_empty_query() -> None:
    """Test validation of empty queries."""
    with pytest.raises(InvalidLDAPQueryError, match="Empty query"):
        LdapSearchFilter.parse("")


def test_validation_no_parentheses() -> None:
    """Test validation of queries without proper parentheses."""
    with pytest.raises(InvalidLDAPQueryError, match="Query must be wrapped in parentheses"):
        LdapSearchFilter.parse("name=test")


def test_validation_empty_parentheses() -> None:
    """Test validation of empty parentheses."""
    with pytest.raises(InvalidLDAPQueryError, match="Empty parentheses found"):
        LdapSearchFilter.parse("()")


def test_validation_invalid_structure() -> None:
    """Test validation of queries with invalid structure."""
    with pytest.raises(InvalidLDAPQueryError, match="Invalid query structure"):
        LdapSearchFilter.parse("((test))")


def test_ldap_wildcards_all_positions() -> None:
    """Test wildcard support in various positions."""
    query1 = "(name=Henk*)"
    parsed1 = LdapSearchFilter.parse(query1, optimize=False)
    assert parsed1.attribute == "name"
    assert parsed1.value == "Henk*"

    query2 = "(name=*son)"
    parsed2 = LdapSearchFilter.parse(query2, optimize=False)
    assert parsed2.attribute == "name"
    assert parsed2.value == "*son"

    query3 = "(givenName=*Jan*)"
    parsed3 = LdapSearchFilter.parse(query3, optimize=False)
    assert parsed3.attribute == "givenName"
    assert parsed3.value == "*Jan*"

    query4 = "(mail=*@*.com)"
    parsed4 = LdapSearchFilter.parse(query4, optimize=False)
    assert parsed4.attribute == "mail"
    assert parsed4.value == "*@*.com"

    query5 = "(&(objectClass=user)(name=*Henk*))"
    parsed5 = LdapSearchFilter.parse(query5, optimize=False)
    assert parsed5.children[1].attribute == "name"
    assert parsed5.children[1].value == "*Henk*"


def test_ldap_parsing_and_no_optimization() -> None:
    query = "(&(objectClass=user)(|(name=Henk)(name=Jan)))"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)
    changed_by_optimizer = parsed_query.query != query
    assert not changed_by_optimizer

    assert len(parsed_query.children) == 2
    assert parsed_query.operator == LdapLogicalOperator.AND
    assert isinstance(parsed_query.children[0], LdapSearchFilter)
    assert parsed_query.children[0].attribute == "objectClass"
    assert parsed_query.children[0].value == "user"
    assert parsed_query.children[0].comparison_operator.value == "="

    assert isinstance(parsed_query.children[1], LdapSearchFilter)
    assert parsed_query.children[1].operator == LdapLogicalOperator.OR
    assert parsed_query.children[1].query == "(|(name=Henk)(name=Jan))"
    assert parsed_query.children[1].children[0].attribute == "name"
    assert parsed_query.children[1].children[0].comparison_operator.value == "="
    assert parsed_query.children[1].children[0].value == "Henk"
    assert parsed_query.children[1].children[1].attribute == "name"
    assert parsed_query.children[1].children[1].comparison_operator.value == "="
    assert parsed_query.children[1].children[1].value == "Jan"


def test_ldap_parsing_and_suboptimal() -> None:
    query = "(&(objectClass=user)(|(name=Henk)(name=Jan)))"
    parsed_query = LdapSearchFilter.parse(query)
    changed_by_optimizer = parsed_query.query != query
    assert changed_by_optimizer

    assert len(parsed_query.children) == 2
    assert parsed_query.operator == LdapLogicalOperator.AND
    assert isinstance(parsed_query.children[1], LdapSearchFilter)
    assert parsed_query.children[1].attribute == "objectClass"
    assert parsed_query.children[1].comparison_operator.value == "="
    assert parsed_query.children[1].value == "user"

    assert isinstance(parsed_query.children[0], LdapSearchFilter)
    assert parsed_query.children[0].operator == LdapLogicalOperator.OR
    assert parsed_query.children[0].query == "(|(name=Henk)(name=Jan))"
    assert parsed_query.children[0].children[0].attribute == "name"
    assert parsed_query.children[0].children[0].comparison_operator.value == "="
    assert parsed_query.children[0].children[0].value == "Henk"
    assert parsed_query.children[0].children[1].attribute == "name"
    assert parsed_query.children[0].children[1].comparison_operator.value == "="
    assert parsed_query.children[0].children[1].value == "Jan"


def test_ldap_parsing_or() -> None:
    query = "(|(name=Henk)(name=Jan))"
    parsed_query = LdapSearchFilter.parse(query)
    changed_by_optimizer = parsed_query.query != query
    assert not changed_by_optimizer

    assert len(parsed_query.children) == 2
    assert parsed_query.operator == LdapLogicalOperator.OR
    assert isinstance(parsed_query.children[0], LdapSearchFilter)
    assert parsed_query.children[0].attribute == "name"
    assert parsed_query.children[0].comparison_operator.value == "="
    assert parsed_query.children[0].value == "Henk"
    assert isinstance(parsed_query.children[1], LdapSearchFilter)
    assert parsed_query.children[1].attribute == "name"
    assert parsed_query.children[1].comparison_operator.value == "="
    assert parsed_query.children[1].value == "Jan"


def test_ldap_parsing_or_2() -> None:
    query = "(&(|(name=Henk)(name=Jan))(surname=de Vries))"
    parsed_query = LdapSearchFilter.parse(query)
    changed_by_optimizer = parsed_query.query != query
    assert not changed_by_optimizer

    assert len(parsed_query.children) == 2
    assert parsed_query.operator == LdapLogicalOperator.AND
    assert isinstance(parsed_query.children[0], LdapSearchFilter)
    assert parsed_query.children[0].query == "(|(name=Henk)(name=Jan))"
    assert len(parsed_query.children[0].children) == 2
    assert isinstance(parsed_query.children[0].children[0], LdapSearchFilter)
    assert parsed_query.children[0].operator == LdapLogicalOperator.OR
    assert parsed_query.children[0].children[0].attribute == "name"
    assert parsed_query.children[0].children[0].comparison_operator.value == "="
    assert parsed_query.children[0].children[0].value == "Henk"
    assert isinstance(parsed_query.children[0].children[1], LdapSearchFilter)
    assert parsed_query.children[0].children[1].attribute == "name"
    assert parsed_query.children[0].children[1].comparison_operator.value == "="
    assert parsed_query.children[0].children[1].value == "Jan"
    assert isinstance(parsed_query.children[1], LdapSearchFilter)
    assert parsed_query.children[1].attribute == "surname"
    assert parsed_query.children[1].comparison_operator.value == "="
    assert parsed_query.children[1].value == "de Vries"


def test_ldap_parsing_nested_and_or() -> None:
    query = (
        "(|(objectClass=container)(objectClass=organizationalUnit)"
        "(sAMAccountType>=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
    )
    parsed_query = LdapSearchFilter.parse(query)
    changed_by_optimizer = parsed_query.query != query
    assert changed_by_optimizer

    assert len(parsed_query.children) == 5

    assert isinstance(parsed_query.children[0], LdapSearchFilter)
    assert parsed_query.children[0].query == "(sAMAccountType>=805306369)"
    assert parsed_query.children[0].attribute == "sAMAccountType"
    assert parsed_query.children[0].comparison_operator.value == ">="
    assert parsed_query.children[0].value == "805306369"

    assert isinstance(parsed_query.children[2], LdapSearchFilter)
    assert parsed_query.children[2].query == "(objectClass=organizationalUnit)"
    assert parsed_query.children[2].attribute == "objectClass"
    assert parsed_query.children[2].comparison_operator.value == "="
    assert parsed_query.children[2].value == "organizationalUnit"

    assert isinstance(parsed_query.children[1], LdapSearchFilter)
    assert parsed_query.children[1].query == "(objectClass=container)"
    assert parsed_query.children[1].attribute == "objectClass"
    assert parsed_query.children[1].comparison_operator.value == "="
    assert parsed_query.children[1].value == "container"

    assert isinstance(parsed_query.children[3], LdapSearchFilter)
    assert parsed_query.children[3].query == "(objectClass=group)"
    assert parsed_query.children[3].attribute == "objectClass"
    assert parsed_query.children[3].comparison_operator.value == "="
    assert parsed_query.children[3].value == "group"

    assert isinstance(parsed_query.children[4], LdapSearchFilter)
    assert parsed_query.children[4].query == "(&(objectCategory=person)(objectClass=user))"
    assert parsed_query.children[4].operator == LdapLogicalOperator.AND
    assert len(parsed_query.children[4].children) == 2
    assert isinstance(parsed_query.children[4].children[0], LdapSearchFilter)
    assert parsed_query.children[4].children[0].query == "(objectCategory=person)"
    assert parsed_query.children[4].children[0].attribute == "objectCategory"
    assert parsed_query.children[4].children[0].comparison_operator.value == "="
    assert parsed_query.children[4].children[0].value == "person"
    assert isinstance(parsed_query.children[4].children[1], LdapSearchFilter)
    assert parsed_query.children[4].children[1].query == "(objectClass=user)"
    assert parsed_query.children[4].children[1].attribute == "objectClass"
    assert parsed_query.children[4].children[1].comparison_operator.value == "="
    assert parsed_query.children[4].children[1].value == "user"


def test_ldap_parsing_single_not() -> None:
    query = "(!(sAMAccountType=805306369))"
    parsed_query = LdapSearchFilter.parse(query)
    changed_by_optimizer = parsed_query.query != query
    assert not changed_by_optimizer

    assert len(parsed_query.children) == 1
    assert parsed_query.operator == LdapLogicalOperator.NOT
    assert isinstance(parsed_query.children[0], LdapSearchFilter)
    assert parsed_query.children[0].attribute == "sAMAccountType"
    assert parsed_query.children[0].comparison_operator.value == "="
    assert parsed_query.children[0].value == "805306369"


def test_ldap_parsing_single_filter_in_condition() -> None:
    query = "(&(objectClass=user))"
    parsed_query = LdapSearchFilter.parse(query)
    changed_by_optimizer = parsed_query.query != query
    assert changed_by_optimizer
    assert parsed_query.query == "(objectClass=user)"


def test_ldap_comparison_operators_less_than_or_equal() -> None:
    """Test <= operator."""
    query = "(age<=30)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert not parsed_query.is_nested()
    assert parsed_query.attribute == "age"
    assert parsed_query.comparison_operator == LdapComparisonOperator.LE
    assert parsed_query.comparison_operator.value == "<="
    assert parsed_query.value == "30"


def test_ldap_comparison_operators_greater_than() -> None:
    """Test > operator."""
    query = "(priority>5)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert not parsed_query.is_nested()
    assert parsed_query.attribute == "priority"
    assert parsed_query.comparison_operator == LdapComparisonOperator.G
    assert parsed_query.comparison_operator.value == ">"
    assert parsed_query.value == "5"


def test_ldap_comparison_operators_less_than() -> None:
    """Test < operator."""
    query = "(score<100)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert not parsed_query.is_nested()
    assert parsed_query.attribute == "score"
    assert parsed_query.comparison_operator == LdapComparisonOperator.L
    assert parsed_query.comparison_operator.value == "<"
    assert parsed_query.value == "100"


def test_ldap_comparison_operators_approximate() -> None:
    """Test ~= operator."""
    query = "(name~=Henk)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert not parsed_query.is_nested()
    assert parsed_query.attribute == "name"
    assert parsed_query.comparison_operator == LdapComparisonOperator.APPROX
    assert parsed_query.comparison_operator.value == "~="
    assert parsed_query.value == "Henk"


def test_ldap_comparison_operators_bit() -> None:
    """Test := operator."""
    query = "(userAccountControl:=2)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert not parsed_query.is_nested()
    assert parsed_query.attribute == "userAccountControl"
    assert parsed_query.comparison_operator == LdapComparisonOperator.BIT
    assert parsed_query.comparison_operator.value == ":="
    assert parsed_query.value == "2"


def test_ldap_all_comparison_operators_in_nested_filter() -> None:
    """Test all comparison operators in nested filter."""
    query = "(&(name=Henk)(age>=18)(score<=100)(priority>5)(weight<75)(description~=admin)(flags:=1024))"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert parsed_query.is_nested()
    assert parsed_query.operator == LdapLogicalOperator.AND
    assert len(parsed_query.children) == 7

    # name = Henk
    assert parsed_query.children[0].attribute == "name"
    assert parsed_query.children[0].comparison_operator.value == "="
    assert parsed_query.children[0].value == "Henk"

    # age >= 18
    assert parsed_query.children[1].attribute == "age"
    assert parsed_query.children[1].comparison_operator.value == ">="
    assert parsed_query.children[1].value == "18"

    # score <= 100
    assert parsed_query.children[2].attribute == "score"
    assert parsed_query.children[2].comparison_operator.value == "<="
    assert parsed_query.children[2].value == "100"

    # priority > 5
    assert parsed_query.children[3].attribute == "priority"
    assert parsed_query.children[3].comparison_operator.value == ">"
    assert parsed_query.children[3].value == "5"

    # weight < 75
    assert parsed_query.children[4].attribute == "weight"
    assert parsed_query.children[4].comparison_operator.value == "<"
    assert parsed_query.children[4].value == "75"

    # description ~= admin
    assert parsed_query.children[5].attribute == "description"
    assert parsed_query.children[5].comparison_operator.value == "~="
    assert parsed_query.children[5].value == "admin"

    # flags := 1024
    assert parsed_query.children[6].attribute == "flags"
    assert parsed_query.children[6].comparison_operator.value == ":="
    assert parsed_query.children[6].value == "1024"


def test_ldap_nested_not_with_different_comparison_operators() -> None:
    """Test NOT with various comparison operators."""
    query = "(!(|(age<18)(score>=90)(userAccountControl:=512)))"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert parsed_query.is_nested()
    assert parsed_query.operator == LdapLogicalOperator.NOT
    assert len(parsed_query.children) == 1

    # Inner OR filter
    inner_filter = parsed_query.children[0]
    assert inner_filter.operator == LdapLogicalOperator.OR
    assert len(inner_filter.children) == 3

    # age < 18
    assert inner_filter.children[0].attribute == "age"
    assert inner_filter.children[0].comparison_operator.value == "<"
    assert inner_filter.children[0].value == "18"

    # score >= 90
    assert inner_filter.children[1].attribute == "score"
    assert inner_filter.children[1].comparison_operator.value == ">="
    assert inner_filter.children[1].value == "90"

    # userAccountControl := 512
    assert inner_filter.children[2].attribute == "userAccountControl"
    assert inner_filter.children[2].comparison_operator.value == ":="
    assert inner_filter.children[2].value == "512"


def test_ldap_complex_nested_with_all_operators() -> None:
    """Test complex nested filters with multiple operators."""
    query = "(&(objectClass=person)(!(department~=temp))(|(age>=21)(|(salary>9000)(title<=manager))))"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert parsed_query.is_nested()
    assert parsed_query.operator == LdapLogicalOperator.AND
    assert len(parsed_query.children) == 3

    # First: (objectClass=person)
    assert parsed_query.children[0].attribute == "objectClass"
    assert parsed_query.children[0].comparison_operator.value == "="
    assert parsed_query.children[0].value == "person"

    # Second: (!(department~=temp))
    not_filter = parsed_query.children[1]
    assert not_filter.operator == LdapLogicalOperator.NOT
    assert not_filter.children[0].attribute == "department"
    assert not_filter.children[0].comparison_operator.value == "~="
    assert not_filter.children[0].value == "temp"

    # Third: (|(age>=21)(|(salary>50000)(title<=manager)))
    or_filter = parsed_query.children[2]
    assert or_filter.operator == LdapLogicalOperator.OR
    assert len(or_filter.children) == 2

    # age >= 21
    assert or_filter.children[0].attribute == "age"
    assert or_filter.children[0].comparison_operator.value == ">="
    assert or_filter.children[0].value == "21"

    # Inner OR: (|(salary>50000)(title<=manager))
    inner_or = or_filter.children[1]
    assert inner_or.operator == LdapLogicalOperator.OR
    assert len(inner_or.children) == 2

    # salary > 50000
    assert inner_or.children[0].attribute == "salary"
    assert inner_or.children[0].comparison_operator.value == ">"
    assert inner_or.children[0].value == "9000"

    # title <= manager (this tests string values with comparison operators)
    assert inner_or.children[1].attribute == "title"
    assert inner_or.children[1].comparison_operator.value == "<="
    assert inner_or.children[1].value == "manager"


def test_ldap_presence_filters() -> None:
    """Test presence filters."""
    # Presence filter - attribute exists
    query = "(mailNickName=*)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert not parsed_query.is_nested()
    assert parsed_query.attribute == "mailNickName"
    assert parsed_query.comparison_operator.value == "="
    assert parsed_query.value == "*"


def test_ldap_absence_filters() -> None:
    """Test absence filters."""
    # Absence filter - attribute does not exist
    query = "(!(proxyAddresses=*))"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    assert parsed_query.is_nested()
    assert parsed_query.operator == LdapLogicalOperator.NOT
    assert len(parsed_query.children) == 1

    inner = parsed_query.children[0]
    assert inner.attribute == "proxyAddresses"
    assert inner.comparison_operator.value == "="
    assert inner.value == "*"


def test_ldap_wildcard_with_different_operators() -> None:
    """Test wildcards with = operator."""
    # Wildcards should work with = operator in all positions
    test_cases = ["(name=Henk*)", "(name=*Henk)", "(name=*Jo*hn*)", "(email=*@domain.com)"]

    for query in test_cases:
        parsed_query = LdapSearchFilter.parse(query, optimize=False)
        assert not parsed_query.is_nested()
        assert parsed_query.attribute in ["name", "email"]
        assert parsed_query.comparison_operator.value == "="
        assert "*" in parsed_query.value


def test_ldap_format_with_all_operators() -> None:
    """Test format() method with all operators."""
    test_cases = [
        ("(name=value)", "name", "=", "value"),
        ("(age>=18)", "age", ">=", "18"),
        ("(score<=100)", "score", "<=", "100"),
        ("(priority>5)", "priority", ">", "5"),
        ("(weight<75)", "weight", "<", "75"),
        ("(desc~=admin)", "desc", "~=", "admin"),
        ("(flags:=1024)", "flags", ":=", "1024"),
    ]

    for expected_query, attr, op_str, val in test_cases:
        query = f"({attr}{op_str}{val})"
        parsed = LdapSearchFilter.parse(query, optimize=False)
        assert parsed.format() == expected_query, f"Failed for {query}"


def test_ldap_error_no_comparison_operator() -> None:
    """Test error for missing comparison operator."""
    query = "(attributename)"
    with pytest.raises(InvalidLDAPQueryError) as exc_info:
        LdapSearchFilter.parse(query, optimize=False)
    assert "No comparison operator found" in str(exc_info.value)
    assert "Expected one of" in str(exc_info.value)


def test_ldap_error_multiple_comparison_operators() -> None:
    """Test error for multiple comparison operators."""
    # This creates a query with both >= and <= operators
    query = "(attribute>=value<=other)"
    with pytest.raises(InvalidLDAPQueryError) as exc_info:
        LdapSearchFilter.parse(query, optimize=False)
    assert "Multiple comparison operators found" in str(exc_info.value)


def test_ldap_repr_nested_filter() -> None:
    """Test __repr__ for nested filters."""
    query = "(&(name=Henk)(age>=18))"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    # Test repr of the main nested filter
    repr_str = repr(parsed_query)
    assert "LdapSearchFilter(NESTED" in repr_str
    assert "operator=LdapLogicalOperator.AND" in repr_str
    assert "children=" in repr_str


def test_ldap_repr_simple_filter() -> None:
    """Test __repr__ for simple filters."""
    query = "(name=Henk)"
    parsed_query = LdapSearchFilter.parse(query, optimize=False)

    repr_str = repr(parsed_query)
    assert 'attribute="name"' in repr_str
    assert 'operator="="' in repr_str
    assert "value=Henk" in repr_str


def test_optimizer_fallback_case() -> None:
    """Test optimizer fallback case."""
    # Create a nested filter that doesn't match other optimization cases

    filter_obj = LdapSearchFilter.__new__(LdapSearchFilter)
    filter_obj.query = "(&)"
    filter_obj.children = []
    filter_obj.operator = LdapLogicalOperator.AND
    filter_obj.attribute = None
    filter_obj.comparison_operator = None
    filter_obj.value = None

    # This should hit the fallback case
    _, weight = optimize_ldap_query(filter_obj)
    assert weight == max(OPTIMIZER_ATTR_WEIGHTS.values())


def test_ldap_extended_matching_rules() -> None:
    """Test extended matching rules."""
    # BIT_AND rule (1.2.840.113556.1.4.803)
    query1 = "(groupType:1.2.840.113556.1.4.803:=8)"
    parsed1 = LdapSearchFilter.parse(query1, optimize=False)

    assert not parsed1.is_nested()
    assert parsed1.attribute == "groupType"
    assert parsed1.comparison_operator == LdapComparisonOperator.EXTENDED_MATCH
    assert parsed1.value == "8"
    assert parsed1._extended_rule == ":1.2.840.113556.1.4.803:="

    # BIT_OR rule (1.2.840.113556.1.4.804)
    query2 = "(userAccountControl:1.2.840.113556.1.4.804:=65568)"
    parsed2 = LdapSearchFilter.parse(query2, optimize=False)

    assert not parsed2.is_nested()
    assert parsed2.attribute == "userAccountControl"
    assert parsed2.comparison_operator == LdapComparisonOperator.EXTENDED_MATCH
    assert parsed2.value == "65568"
    assert parsed2._extended_rule == ":1.2.840.113556.1.4.804:="

    # Test formatting of extended matching rules
    assert parsed1.format() == query1
    assert parsed2.format() == query2


def test_ldap_extended_matching_in_nested_query() -> None:
    """Test extended matching in nested queries."""
    query = "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))"
    parsed = LdapSearchFilter.parse(query, optimize=False)

    assert parsed.is_nested()
    assert parsed.operator == LdapLogicalOperator.AND
    assert len(parsed.children) == 2

    # First child - regular filter
    assert parsed.children[0].attribute == "objectClass"
    assert parsed.children[0].comparison_operator.value == "="
    assert parsed.children[0].value == "group"

    # Second child - extended matching rule
    assert parsed.children[1].attribute == "groupType"
    assert parsed.children[1].comparison_operator == LdapComparisonOperator.EXTENDED_MATCH
    assert parsed.children[1].value == "2147483648"
    assert parsed.children[1]._extended_rule == ":1.2.840.113556.1.4.803:="


def test_ldap_not_operator_optimization() -> None:
    """Test that NOT operators properly optimize their children."""
    # Create a NOT filter with a redundant single-child AND that should be optimized
    query = "(!(&(objectClass=user)))"

    # Parse with optimization enabled
    parsed_optimized = LdapSearchFilter.parse(query, optimize=True)

    # Parse without optimization to compare
    parsed_unoptimized = LdapSearchFilter.parse(query, optimize=False)

    # The optimized version should have simplified the inner (&(objectClass=user)) to just (objectClass=user)
    assert parsed_optimized.operator == LdapLogicalOperator.NOT
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
    complex_parsed = LdapSearchFilter.parse(complex_query, optimize=True)

    # Should optimize to: (!(|(name=Henk)(name=Jan)))
    assert complex_parsed.operator == LdapLogicalOperator.NOT
    inner = complex_parsed.children[0]
    assert inner.operator == LdapLogicalOperator.OR
    assert len(inner.children) == 2
    assert complex_parsed.query == "(!(|(name=Henk)(name=Jan)))"


def test_ldap_real_world_examples() -> None:
    """Test real-world LDAP filter examples."""
    query1 = "(&(objectclass=user)(displayName=Henk))"
    parsed1 = LdapSearchFilter.parse(query1, optimize=False)
    assert parsed1.operator == LdapLogicalOperator.AND
    assert len(parsed1.children) == 2

    query2 = "(!(objectClass=group))"
    parsed2 = LdapSearchFilter.parse(query2, optimize=False)
    assert parsed2.operator == LdapLogicalOperator.NOT
    assert parsed2.children[0].attribute == "objectClass"
    assert parsed2.children[0].value == "group"

    query3 = "(mail=*@henk.nl)"
    parsed3 = LdapSearchFilter.parse(query3, optimize=False)
    assert parsed3.attribute == "mail"
    assert parsed3.value == "*@henk.nl"

    query4 = "(mdbStorageQuota>=100000)"
    parsed4 = LdapSearchFilter.parse(query4, optimize=False)
    assert parsed4.attribute == "mdbStorageQuota"
    assert parsed4.comparison_operator.value == ">="
    assert parsed4.value == "100000"

    query5 = "(displayName~=Henk)"
    parsed5 = LdapSearchFilter.parse(query5, optimize=False)
    assert parsed5.attribute == "displayName"
    assert parsed5.comparison_operator.value == "~="
    assert parsed5.value == "Henk"


def test_ldap_anr_style_filters() -> None:
    """Test ANR-style filters."""
    # Simple ANR-style filter (though ANR itself is server-side)
    query1 = "(anr=Henk)"
    parsed1 = LdapSearchFilter.parse(query1, optimize=False)
    assert parsed1.attribute == "anr"
    assert parsed1.value == "Henk"

    # ANR with partial match
    query2 = "(anr=Henk*)"
    parsed2 = LdapSearchFilter.parse(query2, optimize=False)
    assert parsed2.attribute == "anr"
    assert parsed2.value == "Henk*"


def test_ldap_complex_real_world_filter() -> None:
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

    parsed = LdapSearchFilter.parse(query, optimize=False)
    assert parsed.operator == LdapLogicalOperator.AND
    assert len(parsed.children) == 5

    # Check that all components are parsed correctly
    # objectClass=user
    assert any(child.attribute == "objectClass" and child.value == "user" for child in parsed.children)

    # Extended matching rule for userAccountControl
    bit_filter = next(
        (
            child
            for child in parsed.children
            if child.operator == LdapLogicalOperator.NOT
            and child.children[0].comparison_operator == LdapComparisonOperator.EXTENDED_MATCH
        ),
        None,
    )
    assert bit_filter is not None
    assert bit_filter.children[0].attribute == "userAccountControl"

    # OR condition with wildcards
    or_filter = next((child for child in parsed.children if child.operator == LdapLogicalOperator.OR), None)
    assert or_filter is not None
    assert len(or_filter.children) == 2
    assert "admin*" in [child.value for child in or_filter.children]
    assert "*@admin.*" in [child.value for child in or_filter.children]
