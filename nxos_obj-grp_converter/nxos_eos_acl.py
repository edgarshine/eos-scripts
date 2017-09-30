#!/usr/bin/env python
import re
from collections import defaultdict
import argparse

def main():
    # type: () -> main function
    """
main block function
    """
    parser = argparse.ArgumentParser(description='Convert NX-OS ACL Objects \
                                     to Arista ACLs')
    parser.add_argument('infile', metavar='INPUT_FILE',
                        type=argparse.FileType('r'),
                        help='Name of the file with NX-OS Object ACLs')
    parser.add_argument('outfile', metavar='OUTPUT_FILE', nargs='?',
                        type=argparse.FileType('w'), default='NXOS-EOS-ACL.txt',
                        help='Output file with EOS ACLs')
    args = parser.parse_args()

    input_file = args.infile
    output_file = args.outfile
    input_lines = input_file.readlines()
    object_pattern = 'object-group'
    acl_pattern = 'ip access-list'
    objects_block = []
    acls_block = []
    GetBlocks(list = input_lines, pattern = object_pattern, output = objects_block)
    GetBlocks(list = input_lines, pattern = acl_pattern, output = acls_block)
    objects_dict = defaultdict(list)
    BlockToDict(objects_block, object_pattern, objects_dict)
    address_pattern = "addrgroup"
    port_pattern = "portgroup"
    port_parsed = []
    address_parsed = []
    for acl_line in acls_block:
        BlockParser(acl_line, port_pattern, objects_dict, port_parsed)
    for acl_line in port_parsed:
        BlockParser(acl_line, address_pattern, objects_dict, address_parsed)
    for acl_line in address_parsed:
        output_file.write(acl_line)
    input_file.close()
    output_file.close()

# GetBlocks returns a list with blocks between lines starting with a pattern
# and ending with 'exit'
def GetBlocks(list, pattern, output):
    # type: (nxos_list, patternword, dictname) -> object
    start_rx = re.compile(pattern)
    end_rx = re.compile('exit')
    start = False
    raw_objects = []
    for line in list:
        if ("no "+pattern) not in line:
            if re.match(start_rx, line):
                start = True
            elif re.match(end_rx, line):
                start = False
            if start:
                raw_objects.append(line)
    for index,lines in enumerate(raw_objects):
        if index == 0:
            output.append(lines)
        elif (lines != raw_objects[index - 1]) and (lines != "\n"):
            if pattern not in lines: # remove leading number
                lines_nbr = lines.lstrip().split(' ',1)
                output.append(lines_nbr[1])
            else:
                output.append(lines)
    return

# BlockToDict is intended to map Object-groups to a defaultdict output Dict
def BlockToDict(input_list, pattern, output):
    for input in input_list:
        if pattern in input:
            key = input.split()[-1]
            output[key] = []
        else:
            output[key].append(input)
    return

# BlockParser will separate lines from ACL blocks and replace Object Groups
# returning expanded ACL lines
def BlockParser (acl_line, pattern, object_dict, output):
    segment_list = ["s1", "s2", "s3"]
    object_list = ["o0", "o1"]
    line_split = acl_line.split(pattern)
    if len(line_split) > 3: # Error condition sanity
        print "BLK_PARSER_ERROR: ACL must not have more than two object groups"
        return 
    if len(line_split) == 1: # If line has no object-group just append it
        output.append(acl_line)
        return
    for i, line in enumerate(line_split):
        if i == 0:
            segment_list[i] = line.strip() # First segment
        else:
            object_list[i - 1] = line.lstrip().split(' ',1)[0].strip()
            segment_list[i] = line.lstrip().split(' ',1)[-1].strip() 
            if segment_list[i] == object_list[i - 1]:
                segment_list[i] = ' '
    if len(line_split) > 2: # This means having two object-group in same ACL line
        for object in object_dict[object_list[0]]:
            for object2 in object_dict[object_list[1]]:
                segment_end = ( object2.strip().replace("\n","") 
                                + " "
                                + segment_list[-1]
                              )
                finalstring = ( segment_list[0] 
                                + " "
                                + object.strip().replace("\n","") 
                                + " "
                                + segment_list[1].strip()
                                + " "
                                + segment_end
                                + "\n" 
                              )
                output.append(finalstring)
        return
    else:
        for object in object_dict[object_list[0]]:
            finalstring = ( segment_list[0] 
                            + " "
                            + object.strip().replace("\n"," ") 
                            + " "
                            + str(segment_list[1]) 
                            + "\n" 
                          )
            output.append(finalstring)
        return

if __name__ == "__main__":
   main()
