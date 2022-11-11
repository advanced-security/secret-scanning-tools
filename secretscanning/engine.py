import json
import logging
from typing import List, Dict, Optional
import requests
from ratelimit import limits, sleep_and_retry

from secretscanning.patterns import *


@sleep_and_retry
@limits(calls=30, period=60)
def getSecretScanningLocations(url: str, token: str) -> Dict:
    """Get the locations of a secret scanning alert
    - https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
    """
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.secret-scanner-report-preview+json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        error = f"Failed to get secret scanning results: {response.status_code}"
        logging.error(error)
        raise Exception(error)
    return response.json()


@sleep_and_retry
@limits(calls=30, period=60)
def getSecretScanningResults(
    owner: str, repo: str, token: str, secret_type: Optional[str] = None
) -> List[SecretScanningAlert]:
    """
    - https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
    """
    logging.info(f"Getting secret scanning results for: {owner}/{repo}")
    secrets: List[SecretScanningAlert] = []
    params = {"state": "open"}
    if secret_type:
        params["secret_type"] = secret_type
    url = f"https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.secret-scanner-report-preview+json",
    }
    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        error = f"Failed to get secret scanning results: {response.status_code}"
        logging.error(error)
        raise Exception(error)

    with open("./secrets.json", "w") as f:
        json.dump(response.json(), f, indent=4)

    for secret in response.json():
        locations = getSecretScanningLocations(secret["locations_url"], token)
        for location in locations:
            location = location.get("details")
            secrets.append(
                SecretScanningAlert(
                    secret.get("secret_type"),
                    secret.get("secret_type_display_name"),
                    secret.get("secret"),
                    location.get("path"),
                    location.get("start_line"),
                    location.get("end_line"),
                    location.get("start_column"),
                    location.get("end_column"),
                )
            )
    return secrets
