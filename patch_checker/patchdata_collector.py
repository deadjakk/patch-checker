#!/usr/bin/python3
import re
import sys
import json
import asyncio
import argparse
from pyppeteer import *
from loguru import logger
from pyppeteer import errors
from bs4 import BeautifulSoup

# Example URLs:
#msrcbase    = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0836
#supportbase = https://support.microsoft.com/help/4493475

MSRCBASE      = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/"
SUPPORTBASE   = "https://support.microsoft.com/help/"
BUILD_PATTERN = "14393|15063|16299|17134|17763|10586|10240|18362|18363"

trashbin = []

def parse_row(soup):
    kbs = []
    for item in soup.find_all('div',{"data-automation-key":"product"}):
        if "Windows" in item.text:
            data = item.text.strip()
            build = data
    for item in soup.find_all('div',{"data-automation-key":"kbArticles"}):
        for item in soup.find_all('a',{"class":"ms-Link"}):
            kb = item.text.strip()
            try :
                # test to see if all nums
                int(kb)
                kbs.append(kb)
            except:
                pass
            
        return (build,kbs)

async def parsekb(page,cve):
    retarr = []
    logger.info("Parsing KBs for: {}".format(cve))
    await page.goto(MSRCBASE+cve)

    sel = '#securityUpdates > div:nth-child(1) > div:nth-child(2) > div:nth-child(1)'
    await page.waitForSelector(sel,timeout=20000)
    tableroot = '/html/body/div/div/div/div/div[2]/div/div[2]/div[3]/div/div[5]/div/div/div'
    elements = await page.xpath(tableroot)
    for element in elements:
        outerhtml = await element.getProperty('outerHTML')
        outerhtml = await outerhtml.jsonValue()
        soup = BeautifulSoup(outerhtml, 'html.parser')
        for item in soup.find_all("div",{"class":"ms-List-cell"}):
            res = parse_row(item)
            logger.trace("Found: {}".format(res))
            retarr.append(res)
    return retarr

async def parsesupport(page,inp,cve):
    all_kbs = []
    retarr = []

    for kb in inp[1]:
        kb_f = "KB" + kb
        await page.goto(SUPPORTBASE+kb)
        sel = '#mainContent > div:nth-child(4) > article > div.ng-scope > div:nth-child(1) > div:nth-child(1) > div > div:nth-child(1) > div > header > h1'
        await page.waitForSelector(sel)
        versioninfo = await page.xpath('//*[@id="mainContent"]/div[3]/article/div[2]/div[1]/div[1]/div/div[2]/div[1]/div[1]/div/div[4]/span')
        versionhtml = await versioninfo[0].getProperty('outerHTML')
        version = await versionhtml.jsonValue()
        soup = BeautifulSoup(version, 'html.parser')
        versionre = re.findall(BUILD_PATTERN,soup.text)
        if not versionre:
            versionre = [inp[0]]
        for version in versionre:
            zeroed=False
            elements = await page.xpath('//*[@id="mainContent"]/div[3]/article/div[2]/div[1]/div[1]/div/div[2]/aside/div[2]/div/div/ul')
            for element in elements:
                outerhtml = await element.getProperty('outerHTML')
                outerhtml = await outerhtml.jsonValue()
                soup = BeautifulSoup(outerhtml, 'html.parser')
                for item in soup.find_all("li"):
                    parsedkb = (re.findall("KB[0-9]{7}",item.text))
                    if parsedkb:
                        superseded = parsedkb[0].strip().upper()
                        if not zeroed:
                            all_kbs.append(superseded)
                        if superseded == kb_f:
                            zeroed = True
                            logger.debug("KB_CONVER{}".format(parsedkb))
                            logger.debug("Total KBs found for: {}, {}".format(
                                cve,len(all_kbs)))
                            retarr.append((cve,version,all_kbs))
    return retarr
            
async def parseall(CVE,preview=False):
    browser = await getbrowser()
    page = await browser.newPage()
    arr0 = []
    kbb = await parsekb(page,CVE)
    if not kbb:
        logger.debug("Nothing was returned for {}: {}".format(kbb, CVE))
        return arr0
    logger.debug("Total rows returned for {1}, {0}".format(len(kbb),CVE))

    for kb in kbb:
        if not kb:
            return arr0
        if len(kb[1]) ==0:
            return arr0
        found = False
        while not found:
            try:
                logger.trace("running parsesupport against: {} {}".format(kb,CVE))
                if len(kb[1]) != 0:
                    res = await parsesupport(page,kb,CVE)
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
            '--user-agent="Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.4) Gecko/20100614 Ubuntu/10.04 (lucid) Firefox/3.6.4"'
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
