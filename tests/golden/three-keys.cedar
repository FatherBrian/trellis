// ---- subject ----
@id("access.finance-gl") @mask("pii") @row_filter("region = {person.region}")
permit (
  principal in Group::"finance-analysts",
  action in [Action::"read", Action::"query"],
  resource
)
when {
  resource in Dataset::"finance.gl" &&
  resource.tags.containsAny(["finance"])
};

@id("access.treasury")
permit (
  principal in Group::"treasury",
  action in [Action::"read", Action::"query"],
  resource
)
when {
  resource in Dataset::"finance.treasury" &&
  resource.tags.containsAny(["finance"])
};

@id("access.ana-hr")
permit (
  principal == Person::"ana@example.com",
  action in [Action::"read", Action::"query"],
  resource
)
when {
  resource in Dataset::"hr" &&
  resource.tags.containsAny(["hr"])
};

@id("access.quality")
permit (
  principal in Group::"quality",
  action in [Action::"read", Action::"query"],
  resource
)
when {
  resource in Dataset::"quality" &&
  resource.tags.containsAny(["quality"])
};

@id("purpose.inspection-review")
permit (
  principal == Purpose::"inspection-review",
  action in [Action::"read"],
  resource
)
when {
  ["inspector-bot"].contains(context.agent) &&
  resource in Dataset::"quality" &&
  resource.tags.containsAny(["quality"])
};

// ---- ceiling ----
@id("ceiling.inspector-bot")
permit (
  principal == Agent::"inspector-bot",
  action in [Action::"read"],
  resource
)
when {
  ["quality"].containsAll(resource.tags)
};

@id("ceiling.report-bot")
permit (
  principal == Agent::"report-bot",
  action in [Action::"read", Action::"query"],
  resource
)
when {
  ["finance", "hr", "pii"].containsAll(resource.tags)
};

@id("ceiling.report-bot.never")
forbid (
  principal == Agent::"report-bot",
  action,
  resource
)
when {
  resource.tags.containsAny(["export_controlled"])
};
