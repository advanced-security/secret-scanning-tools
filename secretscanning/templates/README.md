# custom-pattern-secrets

Custom Secret Scanning Patterns repository.

## Patterns

{% for path, config in configs.items() %}
{%- if config.display  %}

### [{{ config.name }}]({{ config.path.replace("/patterns.yml", "") }})

{% for pattern in config.patterns %}
{%- if pattern.experimental == False %}

- {{ pattern.name }}
  {%- endif %}
  {%- endfor %}
  {% endif %}
  {%- endfor %}
