# firewall proxy app

This project implements a Proxy Application in Go, featuring fundamental firewall functionalities, rate limiting, geo-blocking, logging, and a web-based user interface.

## Features

### Basic Firewall Features:

- **Source/Destination IP blocking.**
- **Source/Destination port blocking.**
- **Protocol-based blocking:** Allows blocking specific protocols (e.g., HTTPS).

### Rate Limiting:

- **Request limiting:** Restricts the number of requests from a particular source IP within a specified timeframe (e.g., maximum 100 requests per minute).
- **Bandwidth limiting:** Controls the total bandwidth used by a specific IP or service.

### Geo-blocking:

- Blocks or allows traffic based on the geographical location of the source or destination IP, leveraging a GeoIP database.

### Logging:

- **Comprehensive logging:** Records all blocked traffic, including timestamps, source/destination IPs, and reasons for blocking.
- **Log rotation:** Implements a mechanism to regularly rotate and archive logs.

### Information:

- **Web-based UI:** Facilitates rule configuration, log viewing, and system monitoring for administrators.
- **Statistics display:** Presents bandwidth usage trends over time.

### Test Coverage:

- **Unit tests:** Implemented for both firewall logic and the UI.
- **Coverage goal:** Aiming for at least 80% code coverage.

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Testing](#testing)
4. [Contributing](#contributing)
5. [License](#license)

## Installation (Root permission needed)

1. Clone the repository:

   ```bash
   git clone https://github.com/Pavankalyan9182/firewallproxy
   go mod download
   sudo go run .

