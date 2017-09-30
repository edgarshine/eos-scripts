import argparse
import jsonrpclib
import sys

def main():
   parser = argparse.ArgumentParser(description="Save or check LLDP neighbors")
   parser.add_argument("--switch",
                       help="Hostname or IP of the switch to query")
   parser.add_argument("--username", help="Name of the user to connect as",
                       default="admin")
   parser.add_argument("--password", help="The user's password")
   parser.add_argument("--https", help="Use HTTPS instead of HTTP",
                       action="store_const", const="https", default="http")
   parser.add_argument("--save", help="File where to save the LLDP neighbors")
   parser.add_argument("--check", help="Check that the LLDP neighbors match")
   args = parser.parse_args()

   url = "%s://%s:%s@%s/command-api" % (args.https, args.username,
                                        args.password, args.switch)
   print "Connecting to", url
   eapi = jsonrpclib.Server(url)
   try:
      result = eapi.runCmds(1, ["show lldp neighbors"])
   except jsonrpclib.ProtocolError as e:
      errorResponse = jsonrpclib.loads(jsonrpclib.history.response)
      print "Failed to get the LLDP neighbors:", errorResponse["error"]["data"][0]["errors"][-1]
      sys.exit(1)
   result = result[0]

   if args.check:
      for line in open(args.check):
         port, neighbor = line.strip().split(",")
         #print "Loaded neighbor", neighbor, "on interface", port
         found = False
         for currentNeighbor in result["lldpNeighbors"]:
            if (currentNeighbor["neighborDevice"] == neighbor
                and currentNeighbor["port"] == port):
              found = True
         if not found:
            print "Missing neighbor:", port, "was previously connected to", neighbor

   if args.save:
      with open(args.save, "w") as f:
         for neighbor in result["lldpNeighbors"]:
            f.write("%s,%s\n" % (neighbor["port"], neighbor["neighborDevice"]))


if __name__ == "__main__":
   main()
