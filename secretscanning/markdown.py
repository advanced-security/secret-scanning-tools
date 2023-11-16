import sys
import logging

from jinja2 import Environment, FileSystemLoader

from secretscanning import __here__
from secretscanning.patterns import *


def createMarkdown(root: str, path: str, templates: str = __here__, template_name: str = "template.md", **data) -> str:
    logging.info(f"Creating markdown :: {path}")

    logging.info(f"Template :: {templates}")

    env = Environment(loader=FileSystemLoader(templates))
    template = env.get_template(template_name)

    output_from_parsed_template = template.render(data)

    with open(os.path.join(root, path), "w") as f:
        f.write(output_from_parsed_template)
    return output_from_parsed_template
