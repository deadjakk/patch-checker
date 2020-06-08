import sqlite3
import re
import db_funcs as db
import json
from loguru import logger

supported_builds = [
    "14393",
    "15063",
    "16299",
    "17134",
    "17763",
    "10586",
    "10240",
    "18362",
    "18363",
    "Windows 7 for 32-bit Systems Service Pack 1",
    "Windows 7 for x64-based Systems Service Pack 1",
    "Windows 8.1 for 32-bit systems",
    "Windows 8.1 for x64-based systems",
    "Windows RT 8.1",
    "Windows Server 2008 R2 for Itanium-Based Systems Service Pack 1",
    "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
    "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)",
    "Windows Server 2008 for 32-bit Systems Service Pack 2",
    "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)",
    "Windows Server 2008 for Itanium-Based Systems Service Pack 2",
    "Windows Server 2008 for x64-based Systems Service Pack 2",
    "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)",
    "Windows Server 2012",
    "Windows Server 2012 (Server Core installation)",
    "Windows Server 2012 R2",
    "Windows Server 2012 R2 (Server Core installation)"
]

class NotFound(Exception):
    pass

class PrivChecker:
    def __init__(self,db_f):
        self.db_file = db_f

    def evaluate(self, data, build_data, iscurl=False):
        build = None
        print("-"*25)
        print("Build: {}".format(build))
        print("KBs received: {}".format(data))
        print("Count: {}".format(len(data)))
        print("-"*25)

        for sbuild in supported_builds:
            if build_data == sbuild:
                build = build_data
        # wasn't found in array
        if not build:
            return "Incorrect Build."
        print("Build: {}".format(build))
        vuln_found = []
        cve_query = " DISTINCT cve from vulns where build = '{}'".format(str(build))
        cq_res = None
        try:
            cq_res = db.sqlquery(cve_query,self.db_file,logger)
        except Exception as e:
            logger.error("Error while getting CVEs for build: {}".format(e))
            return "An error occured 1"
        if not cq_res:
            return "Incorrect Build"
        logger.debug("Query result:{}".format(cq_res))
        for cve in cq_res:
            cve = cve[0]
            kbs_query = " DISTINCT kb from vulns where cve = '{}' and build = '{}'".format(cve,build)
            kbs_res = None
            try:
                kbs_res = db.sqlquery(kbs_query,self.db_file,logger)
            except:
                logger.error("Error while getting KBs for build: {}, cve: {}, err{}".format(build,cve,e))
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




