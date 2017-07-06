DBFILE="db/accounts.db"
BUILDFILE="db/buildDB.sql"

if [ -f $DBFILE ];
then
    rm $DBFILE
fi

cat $BUILDFILE | sqlite3 $DBFILE
