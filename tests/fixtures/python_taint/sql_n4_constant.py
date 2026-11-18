# koda-bench: expect=clean rule=code.sql-dynamic-query
def q(cur):
    cur.execute("SELECT count(*) FROM u")
