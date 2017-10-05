#!/usr/bin/python
import urllib2
import os
import sys
import time
import json
import random
import argparse

from bs4 import BeautifulSoup

version = "1.0"
words = []
urls = {"expireddomain": {"get": "/domain-name-search/?q=",
                          "post": "fdomainstart=&fdomain=&fdomainend=&flists%5B%5D=1&ftrmaxhost=0&ftrminhost=0&ftrbl=0&ftrdomainpop=0&ftrabirth_year=0&ftlds%5B%5D=2&button_submit=Apply+Filter&q=",
                          "host":
                              "https://www.expireddomains.net",
                          "referer": "https://www.expireddomains.net/domain-name-search/?q=&searchinit=1"}, \
        "bluecoat": {"get": "/rest/categorization", "post": "url=", "host": "https://sitereview.bluecoat.com",
                     "referer": None}, \
        "checkdomain": {"get": "/cgi-bin/checkdomain.pl?domain=", "post": None,
                        "host": "http://www.checkdomain.com"}}

# Values are in seconds
MIN_BLUECOAT_TIME = 10
MAX_BLUECOAT_TIME = 20


def estimate_bluecoat_time(num_hosts):
    """
    Gives an estimate of long it will take to check Bluecoat. Does a simple expected value calculation assuming a
    uniform distribution in the random wait times.
    :param num_hosts:
    :return:
    """
    avg = (num_hosts * (MIN_BLUECOAT_TIME + MAX_BLUECOAT_TIME)) / 2
    mins = int(avg / 60)
    secs = avg % 60
    output = ""
    if mins > 0:
        output += str(mins) + "m"
    output += str(secs) + "s"
    return output

def check_domain(candidate):
    request = urllib2.Request(urls["checkdomain"]["host"] + urls["checkdomain"]["get"] + candidate.split(".")[0])
    request.add_header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0")
    request.add_header("Referer", urls["checkdomain"]["host"])
    response = urllib2.urlopen(request)
    return (not (response.read().find("is still available") == -1))

def get_hosts_from_keywords(keywords):
    """
    Iterates over all the given keywords and grabs all expired hosts matching the keyword
    :param keywords: keywords search expireddomains.net for
    :return: hosts matching the searched keywords
    """
    hosts = []
    for keyword in keywords:
        request = urllib2.Request(urls["expireddomain"]["host"])
        request.add_header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0")
        response = urllib2.urlopen(request)
        cookies = "ExpiredDomainssessid=" + \
                  response.info().getheader("Set-Cookie").split("ExpiredDomainssessid=")[1].split(";")[0] + "; urih="
        cookies = cookies + response.info().getheader("Set-Cookie").split("urih=")[1].split(";")[0] + "; "

        request = urllib2.Request(urls["expireddomain"]["host"] + urls["expireddomain"]["get"] + keyword)
        request.add_header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0")
        request.add_header("Referer", urls["expireddomain"]["referer"])
        # the _pk_id is hardcoded for now
        request.add_header("Cookie",
                           cookies + "_pk_ses.10.dd0a=*; _pk_id.10.dd0a=5abbbc772cbacfb2.1496158514.1.1496158514.1496158514")
        response = urllib2.urlopen(request, urls["expireddomain"]["post"] + keyword)
        html = BeautifulSoup(response.read(), "html.parser")

        tds = html.findAll("td", {"class": "field_domain"})
        tmp_hosts = []
        for td in tds:
            for a in td.findAll("a", {"class": "namelinks"}):
                tmp_hosts.append(a.text)

        print "[+] (%d) domains found using the keyword \"%s\"." % (len(tmp_hosts), keyword)
        hosts.extend(tmp_hosts)
    if len(keywords) > 1:
        print  "[+] (%d) domains found using (%d) keywords." % (len(hosts), len(keywords))
    return hosts


def get_random_keywords(num=10):
    """
    Gets random keywords from the list of 1,000 most common English words.
    :param num: the number of random keywords to get
    :return: num keywords from the file
    """
    if len(words) == 0:  # Only load file once, even if called multiple times
        try:
            with open('1000-common-words.txt', 'r') as f:
                for line in f:
                    words.append(line.strip())
        except:
            print "Unable to open 1000-common-words.txt. Make sure the file exists and is readable."
    return random.sample(words, num)


def get_category(host):
    """
    Gets the Symantec category for a given host.
    :param host: The host for which to check the category
    :return: the category for the host
    """
    request = urllib2.Request(urls["bluecoat"]["host"] + urls["bluecoat"]["get"])
    request.add_header("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0")
    request.add_header("Origin", urls["bluecoat"]["host"])
    request.add_header("Referer", "https://sitereview.bluecoat.com/sitereview.jsp")
    request.add_header("X-Requested-With", "XMLHttpRequest")
    response = urllib2.urlopen(request, urls["bluecoat"]["post"] + host)
    try:
        json_data = json.loads(response.read())
        if json_data.has_key("errorType"):
            if json_data["errorType"] == "captcha":
                print "[-] Symantec blocked us :("
                sys.exit(0)

        cat = BeautifulSoup(json_data["categorization"], "html.parser")
        cat = cat.find("a")
        cat = cat.text
        return cat
    except:
        print "[-] Something when wrong, unable to get category for %s" % host


def main():
    print "CatMyFish v%s" % version
    print "Mr.Un1k0d3r - RingZer0 Team 2016\n"

    hosts = []
    candidates = []

    parser = argparse.ArgumentParser(description="Search for available already categorized domain")
    parser.add_argument("-v", "--verbose", help="More verbose output", action="store_true")
    parser.add_argument("-e", "--exitone", help="Stop querying Symantec after first success", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--filename", help="Loads domains to check from a text file, instead of searching",
                       type=str)
    group.add_argument("keywords", help="Keyword to use when search for expired domains", nargs='*', default=[])
    group.add_argument("-r", "--random", type=int, help="Chose a random number of common words as keywords")
    parser.add_argument("-o", "--output", type=str, help="Write unregistered, categorized domains to a file.")
    args = parser.parse_args()

    verbose = args.verbose
    exitone = args.exitone
    keywords = args.keywords
    num_random = args.random
    domain_file = args.filename
    output_file = args.output

    # TODO: Need to add more to that list
    blacklisted = ["Phishing", "Web Ads/Analytics", "Suspicious", "Shopping", "Uncategorized", "Placeholders",
                   "Pornography", "Spam", "Gambling", "Scam/Questionable/Illegal", " Malicious Sources/Malnets"]

    if args.verbose:
        print "[+] Verbose mode enabled"

    if args.filename and not os.path.exists(domain_file):
        print "[-] \"%s\" not found." % domain_file
        exit(-1)

    if num_random > 0:
        keywords = get_random_keywords(num_random)
        print "[+] Selected keywords: %s" % ','.join(keywords)

    if not args.filename:
        hosts = get_hosts_from_keywords(keywords)
    else:
        for line in open(domain_file, "rb").readlines():
            hosts.append(line.strip())
        print "[+] (%d) domains loaded." % (len(hosts))

    print "[+] Symantec categorization check may take several minutes. Bot check is pretty aggressive..."
    print "[+] Estimated Time: " + estimate_bluecoat_time(len(hosts))
    for host in hosts:
        if "..." in host:
            if verbose:
                print "[-] Incomplete domain name from ExpiredDomains: %s . Skipping" % host
            next
        cat = get_category(host)
        if not cat in blacklisted:
            print "[+] Potential candidate: %s categorized as %s." % (host, cat)
            candidates.append(host)
            if exitone:
                break
        else:
            if verbose:
                print "[-] Rejected candidate: %s categorized as %s." % (host, cat)

        time.sleep(random.randrange(MIN_BLUECOAT_TIME, MAX_BLUECOAT_TIME))

    print "[+] (%d) candidates found." % (len(candidates))
    f = None
    if output_file:
        f = open(output_file, "w")
    for candidate in candidates:
        if check_domain(candidate):
            print "[+] Awesome \"%s\" is categorized and available." % candidate
            if output_file:
                f.write(candidate + "\n")

    print "[+] Search completed."
    if output_file:
        f.close()


if __name__ == "__main__":
    main()
