<!-- WARNING: This README is generated automatically
-->

<!-- markdownlint-disable no-inline-html -->

# {{ config.name }}

{%- for pattern in config.patterns %}

## {{ pattern.name }}

{% if pattern.experimental -%}
**⚠️ WARNING: THIS RULE IS EXPERIMENTAL AND MIGHT CAUSE A HIGH FALSE POSITIVE RATE (test before commiting to org level) ⚠️**
{%- endif %}
{% if pattern.description -%}
{{ pattern.description }}
{%- endif %}
_version: {{ pattern.regex.version }}_

{% if pattern.comments -%}
**Comments / Notes:**
{% for comment in pattern.comments %}

- {{ comment }}
  {%- endfor %}
  {% endif %}

<details>
<summary>Pattern Format</summary>

```regex
{{ pattern.regex.pattern }}
```

</details>

{% if pattern.regex.start -%}

<details>
<summary>Start Pattern</summary>

```regex
{{ pattern.regex.start }}
```

</details>
{%- endif %}

{%- if pattern.regex.end -%}

<details>
<summary>End Pattern</summary>

```regex
{{ pattern.regex.end }}
```

</details>
{%- endif %}

{%- if pattern.regex.additional_match or pattern.regex.additional_not_match %}

<details>
<summary>Additional Matches</summary>

Add these additional matches to the [Secret Scanning Custom Pattern](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning#example-of-a-custom-pattern-specified-using-additional-requirements).

{% for match in pattern.regex.additional_match %}

- Match:

  ```regex
  {{ match }}
  ```

  {%- endfor %}
  {%- for match in pattern.regex.additional_not_match %}
- Not Match:

  ```regex
  {{ match }}
  ```

  {%- endfor %}

</details>
{%- endif %}
{%- endfor %}
