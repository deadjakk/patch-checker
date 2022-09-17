#!/usr/bin/python3
import re
import sys
import json
import requests as r
import asyncio
import argparse
from pyppeteer import *
from loguru import logger
from pyppeteer import errors
from bs4 import BeautifulSoup

# Example URLs:
#supportbase = https://support.microsoft.com/help/4493475

# provides json output
MSRCAPI       = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?%24filter=cveNumber+eq+%27{}%27"
# used in requests implementation
SUPPORTBASE2 = "https://support.microsoft.com/en-us/help/{}"
# regex pattern
BUILD_PATTERN = "\d{5}|190\d"
OSBUILDPATTERN="OS Build [\d]+"

trashbin = []

def parsebuilds(item):
    retarr =  []
    builds = re.findall(OSBUILDPATTERN,item['releaseVersion'])
    for build in builds:
        build = build.strip().split(' ')[-1]
        build = build.split('.')[0]
        retarr.append(build)
    return retarr
            
        
async def parsekb(page,cve):
    retarr=[]
    response = r.get(MSRCAPI.format(cve.upper()))
    if response.status_code != 200:
        logger.error('error retrieving info from API')
        return False
    data = response.json()
    for item in data['value']:
        if len(item['kbArticles']) == 0:
            logger.info("KB has no kbartices:\n{}\n skipping".format(item))
            continue
        kb = item['kbArticles'][0]['articleName']
        url = item['kbArticles'][0]['articleUrl']
        if kb not in retarr:
            logger.debug('retrieved: {} -> {}'.format(kb,url))
            retarr.append(kb)
    return retarr

def parsesupport(page,inp,cve):
    retarr = []
    all_kbs = {}
    content = []

    for kb in inp:
        go = False
        content = []
        res = r.get(SUPPORTBASE2.format(kb),allow_redirects=True)
        if res.status_code != 200:
            logger.error('did not get 200 when parsing builds and superceded kbs')
            return False


        for line in res.text.splitlines():
            if "supLeftNavCategory supLeftNavActiveCategory" in line:
                content=[]
            if "supLeftNavLink" in line:
                if "Build" in line:
                    content.append(line.strip()) 
            if "aria-current" in line: 
                break

        try:
            for c in content:
                if "Builds" in c:
                    k = c.split("help/")[1].split("\"")[0]
                    #OS Builds 18362.1256 and 18363.1256
                    build1 = c.split("Builds ")[1].split(".")[0]
                    build2 = c.split(" and ")[1].split(".")[0]
                    builds=[build1,build2]
                    for build in builds:
                        if build not in all_kbs.keys():
                            all_kbs[build] = []
                        logger.debug("adding {}:{} for {}".format(k,build,cve))
                        add = "KB{}".format(k)
                        if add not in all_kbs[build]:
                            all_kbs[build].append(add)
                else:
                    k = c.split("help/")[1].split("\"")[0]
                    build = c.split("Build ")[1].split(".")[0]
                    if build not in all_kbs.keys():
                        all_kbs[build] = []
                    logger.debug("adding {}:{} for {}".format(k,build,cve))
                    add = "KB{}".format(k)
                    if add not in all_kbs[build]:
                        all_kbs[build].append(add)
        except Exception as e:
            logger.error(str(e))
    try:
        for k in all_kbs.keys():
            retarr.append((cve,k,all_kbs[k]))
    except Exception as e:
        logger.error(str(e))
    return retarr
            
# calls the other functions to collect the data from msrc
async def parseall(CVE,preview=False):
    browser = await getbrowser()
    page = await browser.newPage()
    arr0 = []
    kbb = await parsekb(page,CVE)
    if not kbb:
        logger.debug("Nothing was returned for {}: {}".format(kbb, CVE))
        return arr0
    logger.debug("Total rows returned for {1}, {0}".format(len(kbb),CVE))

    # example kb item: "#######"
    await asyncio.sleep(3.0) # This one is necessary
    found = False
    while not found:
        try:
            logger.trace("running parsesupport against: {}".format(CVE))
            res = parsesupport(page,kbb,CVE)
            for r in res:
                if r not in arr0:
                    arr0.append(r)
            found = True
        except errors.TimeoutError:
            logger.debug("Browser timed out, restarting")
            browser = await getbrowser(browser)
            page = await browser.newPage()
        except Exception as e:
            logger.error("Received error while grabbing info.\nErr: {}".format(e))
            logger.error("Re-initializing browser and trying again")
            browser = await getbrowser(browser)
            page = await browser.newPage()

    return arr0

def parseall_to_dict(inptup,urls=""):
    print(inptup)
    if not inptup:
        logger.error("Tuple empty")
        return

    retarr=[]
    cve = inptup[0][0]

    retdict = {
        'cve':cve,
        'urls':urls,
        'patch_info':[]
    }

    for item in inptup:
        temp = {}
        temp['build'] = item[1]
        temp['kbs'] = item[2]
        temp['count'] = len(item[2])
        logger.debug('appending: {}'.format(item))
        retdict['patch_info'].append(temp)

    return retdict

def parse_cves(cve_file):
    retarr = []

    with open(cve_file,'r') as fh:
        for line in fh.readlines():
            temp = {}
            line = line.strip()
            re_cve = re.findall("CVE-[0-9]{4}-[0-9]{4,8}",line)
            if not re_cve:
                logger.error("Error parsing cve on line:{}".format(line))
                return
            temp['cve'] = re_cve[0]

            if "|" in line:
                urls = line.split("|")[1]
                urls = urls.replace("," , "\n")
                temp['urls'] = urls

            if temp not in retarr:
                retarr.append(temp)
    return retarr

async def getbrowser(browser=None):
    if browser:
        await browser.disconnect()
        await browser.close()
    headless_opt = True
    if parsed.no_headless:
        headless_opt = False
    logger.debug("starting browser")
    browser=await launch(args=[
            # Startup flags
            '--no-sandbox',
            '--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36/8mqQhSuL-09"'
        ],headless=headless_opt)
    trashbin.append(browser)
    return browser

async def main():
    # parse CVEs from user-provided list
    cvelist = parse_cves(parsed.cve_list)
    logger.info("Loaded {} CVEs".format(len(cvelist)))

    total_output = []
    # Get all related data for a single CVE
    for cve in cvelist:
        res = await parseall(cve['cve'])
        logger.trace("RES>>",res)
        dict_output = parseall_to_dict(res,cve['urls']) 
        logger.trace("Received dict output:{}".format(dict_output))

        total_output.append(dict_output)

    # parsed.json option:
    if parsed.json:
        jf = parsed.json
        if ".json" not in jf:
            jf += ".json"
        with open(jf,'w') as fh:
            try:
                json_out = json.dumps(total_output)
                fh.write(json_out)
                logger.info("Wrote output to {}".format(jf))
            except Exception as e:
                logger.error("Error occured while parsing and writing json file, Err:{}".format(e))
                return

    logger.debug("Alldata:",total_output)
    # parsed.db option:
    if parsed.db:
        import db_funcs as db
        if parsed.new_db:
            db.init_table(parsed.db,logger)
        db.setupdate(parsed.db,logger)

        # write all the data to the vuln table
        logger.info("Writing values to database")
        for cvedict in total_output:
            cve = cvedict['cve']

            # Write the URLs first
            if "\n" in cvedict['urls']:
                urls = cvedict['urls'].split("\n")
            else:
                urls = [cvedict['urls']]

            for url in urls:
                query = {'cve':cve,'url':url}
                db.sqlwrite(parsed.db,'refs',query,logger)
            
            # now write the actual KB data
            for build in cvedict['patch_info']:
                for kb in build['kbs']:
                    query = {
                        'cve':cve,
                        'build':build['build'],
                        'kb':kb
                    }
                    db.sqlwrite(parsed.db,'vulns',query,logger)

    await asyncio.sleep(1.0) # This one is necessary
    print ("finished")
    return

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--cve-list', help="line and pipe separated list containing CVEs and related-URLs with information\n\texample: CVE-2020-1048|https://github.com/ionescu007/faxhell,https://github.com/ionescu007/PrintDemon",required=True)
    parser.add_argument('--db', help="sqlite database filename")
    parser.add_argument('--new-db', help="erases old database (if exists)", action="store_true")
    parser.add_argument('-v', help="set output to debug (verbose)", action="store_true")
    parser.add_argument('-vv', help="set output to annoying", action="store_true")
    parser.add_argument('--no-headless', help="run browser with headless mode disabled",action='store_true')
    parser.add_argument('--json', help="json format output, argument should be json filename")
    parsed = parser.parse_args()

    logger.remove(0) # removes the default logger with a level of 10
    if parsed.v:
        logger.add(sys.stdout,level="DEBUG")
    if parsed.vv:
        logger.add(sys.stdout,level="TRACE")
    else:
        logger.add(sys.stdout,level="INFO")

    logger.debug("args:{}".format(parsed))
    asyncio.get_event_loop().run_until_complete(main())
