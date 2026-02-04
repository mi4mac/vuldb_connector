# VulDB Connector

Connector for the VulDB Vulnerability and CTI API.

## Setup
- Create a VulDB account and personal API key.
- Configure the connector with:
  - `api_key`: Your VulDB personal API key.
  - `base_url`: API endpoint (default `https://vuldb.com/?api`).
  - `api_version`: Major API version (default `3`).
  - `verify_ssl`: Enable or disable SSL verification.

## Health Check
The health check calls the VulDB "recent" endpoint with a count of 1 and
expects a JSON response. If the API key or endpoint is invalid, the check
returns the corresponding error.
If you want to avoid consuming API credits, enable "Skip API Health Check".
When enabled, the health check only verifies the API key is present.
By default this option is enabled and the health check does not call the API.

## Supported Operations
- Get Entry by ID
- Get Recent Entries
- Get Updated Entries
- Search
- Advanced Search
- Vendor Lookup
- Product Lookup
- Get Exploit Status
- Get Exploit Context
- CTI IP Address
- CTI Actor
- CTI Sector
- CTI Events
- CTI Top Activities
- CTI IP List by Date

## Notes
- Use `details` and `cti` options only when needed to reduce credit usage.
- For advanced search syntax and field references, see:
  https://vuldb.com/de/?kb.api
- Supported advanced search keys: vendor, product, version, component, function,
  argument, advisory, researcher, researcher_company, exploit_developer,
  exploit_language, cve, bugtraq, osvdb, xforce, secunia, exploitdb, nessus.
