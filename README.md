Proxy Application in Go
This project introduces a Proxy Application written in Go, encompassing fundamental firewall functionalities, rate limiting, geo-blocking, logging, and a user-friendly web interface.

Features
Basic Firewall Features:
Source/Destination IP blocking.
Source/Destination port blocking.
Protocol-based blocking: Allows blocking specific protocols (e.g., HTTPS).
Rate Limiting:
Request limiting: Restricts the number of requests from a particular source IP within a specified timeframe (e.g., maximum 100 requests per minute).
Bandwidth limiting: Controls the total bandwidth used by a specific IP or service.
Geo-blocking:
Blocks or allows traffic based on the geographical location of the source or destination IP, leveraging a GeoIP database.
Logging:
Comprehensive logging: Records all blocked traffic, including timestamps, source/destination IPs, and reasons for blocking.
Log rotation: Implements a mechanism to regularly rotate and archive logs.
Information:
Web-based UI: Facilitates rule configuration, log viewing, and system monitoring for administrators.
Statistics display: Presents bandwidth usage trends over time.
Test Coverage:
Unit tests: Implemented for both firewall logic and the UI.
Coverage goal: Aiming for at least 80% code coverage.
Static Analysis (Linting):
Code adheres to best practices and standards.
Utilizes golangci-lint.
Table of Contents
Installation
Usage
Testing
Contributing
License
Installation (Root permission needed)
Clone the repository:

bash
Copy code
git clone https://github.com/your-username/your-repo.git
Change to the project directory:

bash
Copy code
cd your-repo
Install dependencies:

bash
Copy code
go mod download
Alternatively, run with Docker:

bash
Copy code
docker build -t firewall .
docker run --publish 8000:8000 --cap-add=NET_ADMIN firewall
Open localhost:8000 in your browser.

Usage (Root permission needed)
Start the application:

bash
Copy code
sudo go run .
Open your browser and navigate to http://localhost:8000.

Testing (Root permission needed)
Run tests:

bash
Copy code
sudo go test ./... -cover -coverprofile=coverage.out
View the test coverage report:

bash
Copy code
sudo go tool cover -func=coverage.out -o=coverage.out
