# patch-checker
## Data Collection: patch_collector.py
---
The `patch_collector.py` script is the pyppeteer scraper that iterates through several Microsoft sites to get the desired data for the cves specified in the `--cve-list` arg file.
For an example of the expected format see the `cves.txt` file within the `samples` directory. Basically it's a line-separated file with each line containing the following `CVE-XXXX-XXXX|https://website.com/resource-pertaining-to-CVE,http://second_resource.com`
you get the idea. An example of the resulting output can be found in the sample.db file included as well.  
The code isn't perfect but it gets the data and works for the time being. As refernce, with 9 CVEs, it should take about 11 minutes to complete, YMMV.

### Help output of patch_collector.py
```
usage: patch_collector.py [-h] --cve-list CVE_LIST [--db DB] [--new-db] [-v]
                          [-vv] [--no-headless] [--json JSON]

optional arguments:
  -h, --help           show this help message and exit
  --cve-list CVE_LIST  line and pipe separated list containing CVEs and
                       related-URLs with information example: CVE-2020-1048|https://github.com/ionescu007/faxhell,https://github.com/ionescu007/PrintDemon
  --db DB              sqlite database filename
  --new-db             erases old database (if exists)
  -v                   set output to debug (verbose)
  -vv                  set output to annoying
  --no-headless        run browser with headless mode disabled
  --json JSON          json format output, argument should be json filename
```

### Example run:

Running `time ./patch_collector.py --cve-list cves.txt  --db antest.db --new-db` yields the following output:
```
2020-06-05 20:38:49.292 | INFO     | __main__:main:181 - Loaded 10 CVEs
2020-06-05 20:38:49.430 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-0836
2020-06-05 20:40:27.183 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1064
2020-06-05 20:41:07.158 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-0841
2020-06-05 20:41:31.675 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1130
2020-06-05 20:42:58.527 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1253
2020-06-05 20:43:25.069 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1315
2020-06-05 20:44:57.974 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1385
2020-06-05 20:45:22.026 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1388
2020-06-05 20:46:48.407 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2019-1405
2020-06-05 20:48:07.026 | INFO     | __main__:parsekb:33 - Parsing KBs for: CVE-2020-1048
finished

real	11m27.793s
user	1m21.632s
sys	0m14.559s
```
