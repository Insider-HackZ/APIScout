package main

import (
	"io"
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"os/exec"
	"sync"
	"time"
)

var wg sync.WaitGroup

func showHelp() {
	// Display available options and flags
	fmt.Println(`
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
`)
}

func checkForNewVersion() {
	const localVersion = "v0.0.1"
	repoURL := "https://api.github.com/repos/Insider-HackZ/APIScout/releases/latest"

	resp, err := http.Get(repoURL)
	if err != nil {
		fmt.Println("Error fetching latest version:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to get latest version: %s\n", resp.Status)
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Println("Error decoding JSON response:", err)
		return
	}

	latestVersion := release.TagName

	if localVersion != latestVersion {
		fmt.Printf("Your version (%s) is outdated. The latest version is %s.\n", localVersion, latestVersion)
		fmt.Print("Do you want to update to the latest version? (y/n): ")

		var choice string
		fmt.Scanln(&choice)

		if choice == "y" {
			fmt.Printf("Updating to version %s...\n", latestVersion)

			cmd := exec.Command("wget", "-O", "APIScout.go", "https://raw.githubusercontent.com/Insider-HackZ/APIScout/refs/heads/main/APIScout.go")
			if err := cmd.Run(); err != nil {
				fmt.Println("Error updating script:", err)
				return
			}

			cmd9 := exec.Command("bash", "-c", "sudo go build APIScout.go")
			if err := cmd9.Run(); err != nil {
				fmt.Println("Error building script:", err)
				return
			}

			cmd10 := exec.Command("bash", "-c", "sudo mv APIScout /usr/local/bin")
			if err := cmd10.Run(); err != nil {
				fmt.Println("Error moving binary:", err)
				return
			}

			fmt.Printf("Update completed || Current Version (%s).\n", latestVersion)
			fmt.Println("Run the tool again....")
			os.Exit(0)
		} else {
			fmt.Println("Update canceled.")
		}
	} else {
		fmt.Printf("You are using the latest version (%s).\n", localVersion)
	}
}

var regexPatterns = map[string]string{
	"google_api":                   `AIza[0-9A-Za-z-_]{35}`,
	"firebase":                     `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
	"google_captcha":               `6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`,
	"google_oauth":                 `ya29\.[0-9A-Za-z\-_]+`,
	"amazon_aws_access_key_id":     `A[SK]IA[0-9A-Z]{16}`,
	"amazon_mws_auth_token":        `amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"amazon_aws_url":               `s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`,
	"amazon_aws_url2":              `([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)`,
	"facebook_access_token":        `EAACEdEose0cBA[0-9A-Za-z]+`,
	"authorization_bearer":         `bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`,
	"authorization_api":            `api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`,
	"mailgun_api_key":              `key-[0-9a-zA-Z]{32}`,
	"twilio_api_key":               `SK[0-9a-fA-F]{32}`,
	"twilio_account_sid":           `AC[a-zA-Z0-9_\-]{32}`,
	"twilio_app_sid":               `AP[a-zA-Z0-9_\-]{32}`,
	"paypal_braintree_access_token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"square_oauth_secret":          `sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`,
	"square_access_token":          `sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`,
	"stripe_standard_api":          `sk_live_[0-9a-zA-Z]{24}`,
	"stripe_restricted_api":        `rk_live_[0-9a-zA-Z]{24}`,
	"github_access_token":          `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`,
	"rsa_private_key":              `-----BEGIN RSA PRIVATE KEY-----`,
	"ssh_dsa_private_key":          `-----BEGIN DSA PRIVATE KEY-----`,
	"ssh_dc_private_key":           `-----BEGIN EC PRIVATE KEY-----`,
	"pgp_private_block":            `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"json_web_token":               `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`,
	"slack_token":                  `\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`,
	"SSH_privKey":                  `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`,
	"heroku_api_key":               `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
}


func checkForAPIKeyLeak(response string) (bool, string, string) {
	for keyName, pattern := range regexPatterns {
		re := regexp.MustCompile(pattern)
		match := re.FindString(response)
		if match != "" {
			return true, keyName, match
		}
	}
	return false, "", ""
}

func sendRequest(wg *sync.WaitGroup, endpoint string, results chan<- string) {
	defer wg.Done()

	resp, err := http.Get(endpoint)
	if err != nil {
		// fmt.Println("Error sending request:", err)
		results <- ""
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// fmt.Println("Error reading response:", err)
		results <- ""
		return
	}

	if found, apiKeyType, leakedKey := checkForAPIKeyLeak(string(body)); found {
		results <- fmt.Sprintf("API Key Leak (%s) found at: %s\nLeaked Key: %s", apiKeyType, endpoint, leakedKey)
	}
}


func processEndpoints(endpoints []string) {
	results := make(chan string, len(endpoints))
	concurrencyLimit := 5
	semaphore := make(chan struct{}, concurrencyLimit)

	for i := 0; i < len(endpoints); i++ {
		semaphore <- struct{}{}
		wg.Add(1)

		go func(endpoint string) {
			defer func() { <-semaphore }()
			sendRequest(&wg, endpoint, results)
		}(endpoints[i])

		time.Sleep(500 * time.Millisecond)
	}

	wg.Wait()
	close(results)

	for result := range results {
		fmt.Println(result)
	}
}

func flag_check() {
	flag_string := os.Args[1:]
	if len(flag_string) == 0 {
		showHelp()
		return
	}
	var domain, domain_list, inputEndpoints string 
	var urls []string
	var foundEndpoints []string // Renamed from endpoints
	var foundEndpoints2 []string // Renamed from endpoints

	for i := 0; i < len(flag_string); i++ {
		if flag_string[i] == "-d" {
			domain = flag_string[i+1]
			break
		} else if flag_string[i] == "-dl" {
			domain_list = flag_string[i+1]
			break
		} else if flag_string[i] == "--endpoints" {
			inputEndpoints = flag_string[i+1]
			fmt.Printf("%s\n", inputEndpoints)
			break
		} else if flag_string[i] == "-h" {
			showHelp()
			return
		}
	}
	checkForNewVersion()
	if domain != "" {
		fmt.Printf("FINDING ENDPOINTS FOR YOUR DOMAIN : %s\n", domain)
		endpoint_finder(domain)
	} else if domain_list != "" {
		fmt.Printf("FINDING ENDPOINTS FOR YOUR DOMAIN LIST: %s\n", domain_list)
		var err error
		urls, err = readURLsFromFile(domain_list)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		for _, url := range urls {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				endpoint_finder(u)
			}(url)
		}
	} else if inputEndpoints != "" {
		fmt.Printf("Endpoints: %s\n", inputEndpoints)
		fileName2 := inputEndpoints
		file2, err := os.Open(fileName2)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file2.Close()

		scanner := bufio.NewScanner(file2)
		for scanner.Scan() {
		foundEndpoints2 = append(foundEndpoints, scanner.Text()) 
		}

		processEndpoints(foundEndpoints2)
		return
	}else{
		showHelp()
		return
	}

	wg.Wait()

	cmd3 := exec.Command("bash", "-c", "cat .tmp/katana_.txt .tmp/waybackurls_.txt | sort -u > .tmp/sorted_.txt")
	cmd3.Run()

	cmd4 := exec.Command("bash", "-c", "cat .tmp/sorted_.txt | wc -l")
	output, err := cmd4.Output()
	if err != nil {
		fmt.Printf("Error executing command: %v\n", err)
		return
	}
	fmt.Printf("Total URL found : %s\n", string(output))
	// cmd5 := exec.Command("bash", "-c", "cat .tmp/sorted_.txt | httpx -o .tmp/on_sorted.txt")
	// cmd5.Run()
	// cmd6 := exec.Command("bash", "-c", "cat .tmp/on_sorted.txt | wc -l")
	// output1, err := cmd6.Output()
	// if err != nil {
	// 	fmt.Printf("Error executing command: %v\n", err)
	// 	return
	// }
	// fmt.Printf("Total ON URL found : %s\n", string(output1))

	fileName := ".tmp/sorted_.txt"
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		foundEndpoints = append(foundEndpoints, scanner.Text()) 
	}

	processEndpoints(foundEndpoints) 
}

func waybackurls(domain string) {
	fmt.Printf("WAYBACKURLS IS RUNNING ON %s......\n", domain)
	cmd2 := exec.Command("bash", "-c", fmt.Sprintf("echo %s | waybackurls >> .tmp/waybackurls_.txt", domain))
	if err := cmd2.Run(); err != nil {
		fmt.Printf("Error running waybackurls: %v\n", err)
	}
}

func katana(domain string) {
	fmt.Printf("KATANA IS RUNNING ON %s......\n", domain)
	cmd1 := exec.Command("bash", "-c", fmt.Sprintf("katana -u %s -silent >> .tmp/katana_.txt", domain))
	if err := cmd1.Run(); err != nil {
		fmt.Printf("Error running katana: %v\n", err)
	}
}

func readURLsFromFile(filePath string) ([]string, error) {
	var urls []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	return urls, nil
}

func endpoint_finder(domain string) {
	cmd := exec.Command("bash", "-c", "mkdir -p .tmp")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		katana(domain)
	}()

	go func() {
		defer wg.Done()
		waybackurls(domain)
	}()
}

func main() {
	Rm_extra()
	banner()
	flag_check()
	Rm_extra()
} 

func banner() {
	fmt.Printf(`
    _    ____ ___ ____                  _
   / \  |  _ \_ _/ ___|  ___ ___  _   _| |_
  / _ \ | |_) | |\___ \ / __/ _ \| | | | __|
 / ___ \|  __/| | ___) | (_| (_) | |_| | |_
/_/   \_\_|  |___|____/ \___\___/ \__,_|\__|
		   Developed by: harshj054
`)
}

func Rm_extra() {
	cmd8 := exec.Command("bash", "-c", "rm -r .tmp")
	cmd8.Run()
}
