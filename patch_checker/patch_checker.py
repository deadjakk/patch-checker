import sqlite3
import re
import db_funcs as db
import json
from loguru import logger

supported_builds = [
    "10240",
    "14393",
    "15063",
    "15254",
    "16299",
    "17134",
    "17763",
    "18362",
    "18363",
    "19041",
    "19042",
    "19043",
    "19044",
    "OS 17763",
    "20348",
    "22000",
]

class NotFound(Exception):
    pass

class PrivChecker:
    def __init__(self,db_f):
        self.db_file = db_f

    def evaluate(self, data, build_data, iscurl=False):
        build = None
        print("-"*25)
        print("KBs received: {}".format(data))
        print("Count: {}".format(len(data)))

        if len(data) == 0:
            logger.error("no KBs supplied")
            return "You must supply KBs to check"
        build = build_data if build_data in supported_builds else None
        # wasn't found in array
        if not build:
            logger.error("invalid build supplied", repr(build_data), supported_builds)
            return "Incorrect Build."
        print("Build: {}".format(build))
        print("-"*25)

        vuln_found = []
        cq_res = None
        cve_query = f" DISTINCT cve from vulns where build = \"{build}\""
        try:
            cq_res = db.sqlquery(cve_query,self.db_file,logger)
        except Exception as e:
            logger.error("Error while getting CVEs for build: {}".format(e))
            return "An error occured"
        if not cq_res:
            logger.error(f"no cves found for {build}")
            return "No CVEs for provided build"
        logger.debug("Query result:{}".format(cq_res))
        for cve in cq_res:
            cve = cve[0]
            kbs_query = " DISTINCT kb from vulns where cve = '{}' and build = '{}'".format(cve,build)
            kbs_res = None
            try:
                kbs_res = db.sqlquery(kbs_query,self.db_file,logger)
            except:
                logger.error(f"Error while getting KBs for build: {build}")
                return "Error performing query"
            if not kbs_res:
                return "An error occured 2"

            vuln = True
            for kb in kbs_res:
                kb = kb[0]
                if kb in data:
                    logger.debug("Not vulnerable to: {}".format(cve))
                    vuln = False

            if vuln:
                vuln_found.append(cve)

        # Getting the date the database was last updated
        date = "Who knows?"
        try:
            date = db.lastupdate(self.db_file,logger)
        except:
            logger.error("Error while getting date: err{}".format(e))

        # building output for vulnerable CVEs that were found
        print("Vulnerable to:{}, total: {}".format(vuln_found,len(vuln_found)))

        # curl output:
        if iscurl:
            logger.debug("Received curl query")
            rdict = {}
            rdict['total_vuln'] = len(vuln_found)
            rdict['db_last_updated'] = str(date)
            rdict['kbs_parsed'] = []
            rdict['total_kbs_parsed'] = len(data)
            rdict['build'] = build
            rdict['results'] = []
            for kb in data:
                rdict['kbs_parsed'].append(kb)
            for cve in cq_res:
                cve = cve[0]

                tdict = {}
                tdict['refs'] = []
                tdict['name'] = cve
                if cve in vuln_found:
                    tdict['vulnerable'] = True
                    url_query = " * from refs where cve = '{}' ".format(cve)
                    url_res = None
                    try:
                        url_res = db.sqlquery(url_query,self.db_file,logger)
                    except:
                        logger.error("Error while getting urls for cve: {}, err{}".format(cve,e))
                        return "Error performing query"
                    for item in url_res:
                        tdict['refs'].append(item[1])
                else:
                    tdict['vulnerable'] = False
                rdict['results'].append(tdict)
            jsonout = ""
            try:
                jsonout = json.dumps(rdict)
                return jsonout
            except Exception as e:
                logger.error("Error parsing json: {}".format(e))
                return "Error parsing json"
        
        # Browser output:
        output = ''
        output += 'Database last updated: <strong>{}</strong>\n'.format(str(date))
        output += 'Tested against build: <strong>{}</strong>\n'.format(build)
        output += 'Parsed the following patches ({})\n'.format(len(data))
        row = 0
        for kb in data:
            row += 1 
            output += "<strong>{}</strong>".format(kb)
            if (row %3) != 0 and kb != data[-1]:
                output += " | "
            else:
                output += "\n"
        output += "\n"

        for cve in cq_res:
            cve = cve[0]
            output += "Check: {} Result: ".format(cve)
            if cve in vuln_found:
                output += "<span class='v'>Vulnerable    </span>"
                url_query = " * from refs where cve = '{}' ".format(cve)
                url_res = None
                try:
                    url_res = db.sqlquery(url_query,self.db_file,logger)
                except:
                    logger.error("Error while getting urls for cve: {}, err{}".format(cve,e))
                    return "Error performing query"
                for item in url_res:
                    output += "<pre>\t<a href='{0}'>{1}</a></pre>".format(item[1],item[1])
            else:
                output += "<span class='nv'>Not Vulnerable</span>\n\n"

        return output
