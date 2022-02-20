clientIPs = [("127.0.0.1", 5051), ("127.0.0.1", 5052), ("127.0.0.1", 5053), ("127.0.0.1", 5054), ("127.0.0.1", 5055)]
CLIENTNUM = 5

FOLLOWER = 1
CANDIDATE = 2
LEADER = 3

ELECTION = 1
RESPONDELECTION = 2
APPEND = 3
RESPONDAPPEND = 4

clientGraph = [[0, 1, 1, 1, 1],
               [1, 0, 1, 1, 1],
               [1, 1, 0, 1, 1],
               [1, 1, 1, 0, 1],
               [1, 1, 1, 1, 0]]
