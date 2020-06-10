import sqlite3
import time

def create_conn(db_file,logger):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        logger.error("Error creating sqlite3 connection")
    return conn

def sqldroptable(conn,tablename,logger):
    try:
        conn.execute("DROP TABLE IF EXISTS {}".format(tablename))
        logger.debug("dropped {} table".format(tablename))
        return True
    except Exception as e:
        logger.error("sqlerror dropping table: {}".format(e))
        return False

def sqlquery(query,db_file,logger):
    conn = create_conn(db_file,logger)
    cur = conn.cursor()
    try:
        cur.execute("select {}".format(query))
    except Exception as e:
        logger.error("sqlquery error: {}".format(e))

    rows = cur.fetchall()
    retarr = []
    for row in rows:
        retarr.append(row)
    return retarr

def init_table(dbname,logger):
    conn = create_conn(dbname,logger)
    sqldroptable(conn,'vulns',logger)
    sqldroptable(conn,'date',logger)
    sqldroptable(conn,'refs',logger)
    queries = [
            "create table date(\
                last_updated varchar(120)\
             )",                          
            "create table vulns(\
                build varchar(32),\
                cve varchar(24),\
                kb varchar (16), \
                UNIQUE(build,cve,kb) ON CONFLICT IGNORE\
             )",                          
            "create table refs(\
                cve varchar(24),\
                url varchar(200),\
                UNIQUE(url,cve) ON CONFLICT IGNORE\
             )"                            
    ]
    with conn:
        for query in queries:
            try:
                logger.debug("Executing query: {}".format(query))
                conn.execute(query)
            except Exception as e:
                logger.error("Query failed: {}".format(query))
                logger.error("qError:{}".format(e))
                return e

def setupdate(dbname,logger):
    query = {"last_updated":time.asctime()}
    try:
        sqlwrite(dbname,'date',query,logger)
        logger.debug("setting date")
    except Exception as e:
        logger.error("Query failed: {}".format(query))

def lastupdate(dbname,logger):
    query = " last_updated from date order by last_updated DESC limit 1"
    try:
        out = sqlquery(query,dbname,logger)
        logger.debug("date is: {}".format(out[0][0]))
    except Exception as e:
        logger.debug("Failed to get time: Err:{}".format(e))
        return "failed to get updated time"
    if not out:
        return " who knows ? "
    return out[0][0]


def sqlwrite(dbname,tablename,data,logger):
    # formatting data prior to insertion
    for i in data.keys():
        if type(data[i]) == list:
            data[i] = ",".join(data[i])
        else:
            pass
    query = "INSERT INTO {}({}) VALUES( {} )".format(tablename,
    ",".join(data.keys()),
    ", ".join("?"*len(data.keys()))
    )
    query = "INSERT INTO " + tablename + "(" + ",".join(data.keys()) + ") VALUES(" +", ".join("?"*len(data.keys()))+")"
    logger.trace("Executing query: {}".format(query))
    conn = create_conn(dbname,logger)
    with conn:
        try:
            conn.execute(query,tuple(data.values()))
            logger.debug("successfully added data to database\n\tnew values:{}".format(data.values()))
            return True
        except sqlite3.IntegrityError:
            logger.trace("sqlwrite: user attempted to create duplicate job\n:{}".format(data.values()))
            return "duplicate"
        except Exception as e:
            logger.warning("sqlwrite Error: {}".format(e))
            return 

