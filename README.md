# APIScout

APIScout is a powerful tool designed for cybersecurity pentesters to find leaked API keys and sensitive information across website endpoints. It scans domains or lists of URLs to detect API key leaks based on predefined regular expressions for various services such as Google, AWS, GitHub, and more.

## Features

- Supports scanning a single domain or multiple domains from a file.
- Scans specified endpoints for potential API key leaks.
- Concurrent requests for faster processing.
- Auto-check for tool updates from GitHub.

## Installation

To use **APIScout**, you need Go installed on your system.

Clone the repository:

```
git clone https://github.com/Insider-HackZ/APIScout.git  
cd APIScout
chmod +x setup.sh
sudo ./setup.sh
```

## Usage

### Command Line Options

```
Usage: APIScout [OPTIONS]

Options:
  -d    <domain>              Provide a single domain for which you want to find endpoints.
  -dl   <domain_list>         Provide a list of domains from a file for which you want to find endpoints.
  --endpoints <url_list>      Provide a list of endpoints to scan for API key leaks.
  
  -h                          Display this help message and exit.

Examples:
  APIScout -d example.com
  APIScout -dl domains.txt
  APIScout --endpoints urls.txt
```

### Scanning a Single Domain

To scan a single domain for API key leaks:

```
APIScout -d example.com
```

### Scanning Multiple Domains

To scan multiple domains from a file:

```
APIScout -dl domains.txt
```

Where `domains.txt` contains a list of domains to scan.

### Scanning Specific Endpoints

To scan specific endpoints for potential API key leaks:

```
APIScout --endpoints urls.txt
```

Where `urls.txt` contains a list of URLs.

## API Key Detection

APIScout uses regex patterns to find the following types of API keys:

- Google API Keys
- AWS Access Keys
- Facebook Access Tokens
- GitHub Tokens
- And many more...

## **Credits**

Developed by: [harshj054](https://www.linkedin.com/in/harsh-jain-7648382b7/)

> If anyone would like to contribute to the development of Insider-HackZ/APIScout, please send an email to [official@bytebloggerbase.com](mailto:official@bytebloggerbase.com).
