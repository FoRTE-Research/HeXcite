#!/usr/bin/python3

import os, sys
from capstone import *

######################################

oracleZaflDir  = ""	# Path to oracle Zipr dir
tracerZaflDir  = ""	# Path to tracer Zipr dir
outMapPath     = ""	# Path to output mapping
outLogPath     = "" # Path to output error log

outLogFile = ""

oracleZiprMap = set() 
oracleZaxMap  = set()
tracerZaxMap  = set()
oracleCebMap  = set()  	
tracerCebMap  = set()		

######################################

# zipr.map mapping of insn's to addr's.

class ZiprEntry:
	addr = ""
	insn = ""
	mnem = ""

	def __init__(self, insn, addr, mnem):
		self.insn = insn
		self.addr = addr	
		self.mnem = mnem


# zax.map mapping of bbid's to insn's.

class ZaxEntry:
	bbid = ""
	insn = "" 

	def __init__(self, bbid, insn):
		self.bbid = bbid
		self.insn = insn


# ceb.map mapping of each critical edge.

class CebEntry:
	insnOld = "" # The edge's starting insn.
	insnNew = "" # The edge's ending insn.
	broken = ""
	etype = ""

	def __init__(self, insnOld, insnNew, broken, etype):
		self.insnOld = insnOld
		self.insnNew = insnNew
		self.broken = broken
		self.etype = etype	


# Object for output map entries. 

class MapEntry:
	bbid = ""     # Tracer block ID (aka AFL-SHM index).
	addr = ""     # Corresponding oracle address.
	modAddr = ""  # Oracle addr where interrupt will be written.
	modLen = ""   # Length of interrupt bytes.
	modBytes = "" # Interrupt bytes (e.g., 0xCC).

	def __init__(self, bbid, addr, modAddr, modLen, modBytes):
		self.bbid = bbid
		self.addr = addr
		self.modAddr = modAddr
		self.modLen = modLen
		self.modBytes = modBytes	


######################################

# Parse zipr.map into ZiprEntry objs.

def load_zipr_map(ZiprMapPath):
	ZiprMap = set()

	with open(ZiprMapPath) as f:
		for line in f.readlines()[1:]:
			line = line.strip().split()
			insn = int(line[0],16)
			addr = line[3]
			mnem = line[5]

			entry = ZiprEntry(insn, addr, mnem)
			ZiprMap.add(entry)

	return ZiprMap


# Parse zax.map into ZaxEnt objs.

def load_zax_map(ZaxMapPath):
	ZaxMap = set()

	with open(ZaxMapPath) as f:
		for line in f.readlines()[1:]:
			line = line.strip().split()
			bbid = int(line[0],16)
			insn = int(line[1].split(":")[0],16)

			entry = ZaxEntry(bbid, insn)
			ZaxMap.add(entry)

	return ZaxMap


# Parse ceb.map into CebEntry objs.

def load_ceb_map(CebMapPath):
	CebMap = set()

	if (not os.path.exists(CebMapPath)):
		return CebMap

	with open(CebMapPath) as f:
		for line in f.readlines()[1:]:
			line = line.strip().split()
			insnOld = int(line[0],16)
			broken  = line[1]
			etype   = line[2]
			insnNew = int(line[3],16)

			entry = CebEntry(insnOld, insnNew, broken, etype)
			CebMap.add(entry)

	return CebMap


# Compute 2's complement from integer. Borrowed from: 
# https://stackoverflow.com/a/43359133

def get_hex_from_int(num):
	OFFSET = 1 << 32
	MASK = OFFSET - 1

	dump = '%08x' % (num + OFFSET & MASK)
	out = []

	for i in range(0, 4):
		out.append('0x' + dump[i * 2: i * 2 + 2])

	return out[::-1]  # return in little endian


# Compute base-adjusted address. Necessary for binaries
# whose base address is 0x400000. TODO: string-handling.

def get_base_addr(addr):
	base = int(0x400000)
	addr = int(addr,16)

	if (addr > base):
		addr = addr-base

	return addr


# Use Capstone to disassemble some bytes to an instruction
# and verify its length = 6. Used in jump mistargeting to
# separate a cond. JMP's mnemonic bytes from operand bytes.

def disassemble(someBytes):
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.syntax = CS_OPT_SYNTAX_ATT
	md.detail = True
	disas = list(md.disasm(someBytes, 0))[0]

	if disas.size != 6:
		print ("ERROR!")
		return "",""

	return someBytes[0:2], someBytes[2:6]


# Read some bytes of a binary at a given base address.

def read_bytes(addrBase, binary):
	dump = open(binary, "rb+")
	dump.seek(addrBase, 0)
	someBytes = dump.read(12) 
	dump.close()

	return someBytes


# Compute the new address after adding some number
# of offset bytes. TODO: string-handling.

def addr_plus_offset(addr, offset):
	addrBase = get_base_addr(addr)
	addrNew = addrBase + 2
	addrNew += int(0x400000)
	addrNew = hex(addrNew)[2:]

	return addrNew


######################################

# Map standard (non-critical-edge) blocks. These 
# receive just aone-byte interrupt at their start.

def map_standard_blocks():
	outMap = []

	for ZaxEnt in tracerZaxMap:

		# If the block splits a critical edge, skip it.

		if ZaxEnt.insn in [CebEnt.insnNew for CebEnt in tracerCebMap]:
			continue

		# Find the tracer Zax entry's matching oracle Zipr entry.

		matches = [ZiprEnt for ZiprEnt in oracleZiprMap if ZiprEnt.insn == ZaxEnt.insn]

		# If we've found a match, map for a one-byte interrupt!
		
		if (len(matches) == 1):
			ZiprEnt = matches[0]
			entry = MapEntry(ZaxEnt.bbid, ZiprEnt.addr, ZiprEnt.addr, 1, "0xCC")
			outLogFile.write("Found block: " \
				"[bbid:%s, addr:%s]\n" % (ZaxEnt.bbid, ZiprEnt.addr))
			outMap.append(entry)	

		# Handle discrepancies.

		if (len(matches) > 1):
			outLogFile.write("ERR_MULT: multiple oracle ZiprEnt's for tracer ZaxEnt: " \
				"[bbid:%s, insn:%s]\n" % (ZaxEnt.bbid, ZaxEnt.insn))
			continue

		if (len(matches) == 0):
			outLogFile.write("ERR_ZERO: zero oracle ZiprEnt's for tracer ZaxEnt: " \
				"[bbid:%s, insn:%s]\n" % (ZaxEnt.bbid, ZaxEnt.insn))
			continue

	return outMap


# Map blocks splitting fall-thru critical edges. 
# These also receive just a one-byte interrupt.

def map_critedge_split():
	outMap = []

	for oracleCebEnt in oracleCebMap:

		# If the critical edge is NOT split, ignore it.

		if (oracleCebEnt.broken == "false"):
			continue

		# Find its matching tracer Ceb entry.

		matchesCeb = [tracerCebEnt for tracerCebEnt in tracerCebMap if \
				((tracerCebEnt.insnOld == oracleCebEnt.insnOld) and \
				(tracerCebEnt.etype == oracleCebEnt.etype))]

		if (len(matchesCeb) == 1):

			# Find the tracer Ceb entry's matching tracer Zax entry.

			tracerCebEnt = matchesCeb[0]
			matchesZax = [ZaxEnt for ZaxEnt in tracerZaxMap if \
						ZaxEnt.insn == tracerCebEnt.insnNew]
			
			if (len(matchesZax) == 1):

				# Find the tracer Zax entry's matching oracle Zipr entry.
				# Since the block is split in the oracle, we want to match
				# based on critical edge's new (destination) instruction.

				ZaxEnt = matchesZax[0]
				matchesZipr = [ZiprEnt for ZiprEnt in oracleZiprMap if \
						ZiprEnt.insn == oracleCebEnt.insnNew]

				# If we've found a match, map for a one-byte interrupt!

				if (len(matchesZipr) == 1):
					ZiprEnt = matchesZipr[0]
					entry = MapEntry(ZaxEnt.bbid, ZiprEnt.addr, ZiprEnt.addr, 1, "0xCC")
					outLogFile.write("Found cedge (split): " \
						"[bbid:%s, addr:%s]\n" % (ZaxEnt.bbid, ZiprEnt.addr))
					outMap.append(entry)	

				# Handle discrepancies.

				if (len(matchesZipr) > 1):
					outLogFile.write("ERR_MULT: multiple oracle ZiprEnt's for tracer ZaxEnt: " \
						"[bbid:%s, insn:%s]\n" % \
						(ZaxEnt.bbid, ZaxEnt.insn))
					continue

				if (len(matchesZipr) == 0):
					outLogFile.write("ERR_ZERO: zero oracle ZiprEnt's for tracer ZaxEnt: " \
						"[bbid:%s, insn:%s]\n" % \
						(ZaxEnt.bbid, ZaxEnt.insn))
					continue

			# Handle discrepancies.

			if (len(matchesZax) > 1):
				outLogFile.write("ERR_MULT: multiple tracer ZaxEnt's for tracer CebEnt: " \
					"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
					(tracerCebEnt.insnOld, tracerCebEnt.insnNew, \
					tracerCebEnt.etype, tracerCebEnt.broken))
				continue

			if (len(matchesZax) == 0):
				outLogFile.write("ERR_ZERO: zero tracer ZaxEnt's for tracer CebEnt: " \
					"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
					(tracerCebEnt.insnOld, tracerCebEnt.insnNew, \
					tracerCebEnt.etype, tracerCebEnt.broken))
				continue

		# Handle discrepancies

		if (len(matchesCeb) > 1):
			outLogFile.write("ERR_MULT: multiple tracer CebEnt's for oracle CebEnt: " \
				"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
				(oracleCebEnt.insnOld, oracleCebEnt.insnNew, \
				oracleCebEnt.etype, oracleCebEnt.broken))
			continue
		
		if (len(matchesCeb) == 0):
			outLogFile.write("ERR_ZERO: zero tracer CebEnt's for oracle CebEnt: " \
				"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
				(oracleCebEnt.insnOld, oracleCebEnt.insnNew, \
				oracleCebEnt.etype, oracleCebEnt.broken))
			continue

	return outMap


# (Jump Mistargeting) Map the oracle's unsplit cond. 
# jump target critical edges. Since these edges are not
# split we can't use one-byte interrupts at a block start.
# Instead, we rewrite the jump insn's operand to resolve
# the target (taken) branch to the zero-address, which
# will halt the program just like an interrupt would. 

def map_critedge_jmpmis():
	outMap = []

	for oracleCebEnt in oracleCebMap:

		# If the critical edge IS split, ignore it.

		if (oracleCebEnt.broken == "true"):
			continue

		# Find its matching tracer Ceb entry.

		matchesCeb = [tracerCebEnt for tracerCebEnt in tracerCebMap if \
				((tracerCebEnt.insnOld == oracleCebEnt.insnOld) and \
				(tracerCebEnt.etype == oracleCebEnt.etype))]

		if (len(matchesCeb) == 1):

			# Find the tracer Ceb entry's matching tracer Zax entry.

			tracerCebEnt = matchesCeb[0]
			matchesZax = [ZaxEnt for ZaxEnt in tracerZaxMap if \
						ZaxEnt.insn == tracerCebEnt.insnNew]
			
			if (len(matchesZax) == 1):

				# Find the tracer Zax entry's matching oracle Zipr entry.
				# Since the block isn't split in the oracle, we want to 
				# match based on critical edge's old (source) instruction.

				ZaxEnt = matchesZax[0]
				matchesZipr = [ZiprEnt for ZiprEnt in oracleZiprMap if \
						ZiprEnt.insn == oracleCebEnt.insnOld]

				# If we've found a match, read the bytes at the insn's addr,
				# and disassemble it. Then, compute the mistargeted address
				# (which will resolve the jump to 0) and corresponding bytes.

				if (len(matchesZipr) == 1):
					ZiprEnt = matchesZipr[0]

					addr      = ZiprEnt.addr
					addrBase  = get_base_addr(addr)

					insnBytes = read_bytes(addrBase, ("%s/c.out" % oracleZaflDir))
					(mnemBytes,targBytes) = disassemble(insnBytes)

					jmTargBase  = -1*(addrBase + 6)
					jmTargBytes = get_hex_from_int(jmTargBase)
					jmModAddr   = addr_plus_offset(addr, 2)

					entry = MapEntry(ZaxEnt.bbid, ZiprEnt.addr, jmModAddr, 4, " ".join(jmTargBytes))

					outLogFile.write("Found cedge (jmpmis): " \
						"[bbid:%s, addr:%s]\n" % (ZaxEnt.bbid, ZiprEnt.addr))
					outMap.append(entry)

				# Handle discrepancies.	

				if (len(matchesZipr) > 1):
					outLogFile.write("ERR_MULT: multiple oracle ZiprEnt's for tracer ZaxEnt: " \
						"[bbid:%s, insn:%s]\n" % \
						(ZaxEnt.bbid, ZaxEnt.insn))
					continue

				if (len(matchesZipr) == 0):
					outLogFile.write("ERR_ZERO: zero oracle ZiprEnt's for tracer ZaxEnt: " \
						"[bbid:%s, insn:%s]\n" % \
						(ZaxEnt.bbid, ZaxEnt.insn))
					continue

			# Handle discrepancies.

			if (len(matchesZax) > 1):
				outLogFile.write("ERR_MULT: multiple tracer ZaxEnt's for tracer CebEnt: " \
					"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
					(tracerCebEnt.insnOld, tracerCebEnt.insnNew, \
					tracerCebEnt.etype, tracerCebEnt.broken))
				continue

			if (len(matchesZax) == 0):
				outLogFile.write("ERR_ZERO: zero tracer ZaxEnt's for tracer CebEnt: " \
					"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
					(tracerCebEnt.insnOld, tracerCebEnt.insnNew, \
					tracerCebEnt.etype, tracerCebEnt.broken))
				continue

		# Handle discrepancies.

		if (len(matchesCeb) > 1):
			outLogFile.write("ERR_MULT: multiple tracer CebEnt's for oracle CebEnt: " \
				"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
				(oracleCebEnt.insnOld, oracleCebEnt.insnNew, \
				oracleCebEnt.etype, oracleCebEnt.broken))
			continue

		if (len(matchesCeb) == 0):
			outLogFile.write("ERR_ZERO: zero tracer CebEnt's for oracle CebEnt: " \
				"[insnOld:%s, insnNew:%s, etype:%s, broken:%s]\n" % \
				(oracleCebEnt.insnOld, oracleCebEnt.insnNew, \
				oracleCebEnt.etype, oracleCebEnt.broken))
			continue

	return outMap


# Main body

def main():
	global oracleZaflDir, oracleZiprMap, \
		oracleZaxMap, tracerZaxMap, \
		oracleCebMap, tracerCebMap, \
		outLogFile

	usage = "\n\tUsage: " \
		"\thexcite-mapper.py " \
		"[/path/to/oracle/ZAFL/dir] [/path/to/tracer/ZAFL/dir] " \
		"[/path/to/outmap] [/path/to/maplog]\n"

	# Get args and open file handlers.

	if len(sys.argv) < 5:
		print ("Missing argument(s)!")
		print (usage)
		exit(1)

	outMapPath = sys.argv[3]
	outLogPath = sys.argv[4]
	outMapFile = open(outMapPath, "w+")
	outLogFile = open(outLogPath, "w+")

	# Load maps and process. 

	oracleZaflDir = sys.argv[1]
	tracerZaflDir = sys.argv[2]	

	oracleZiprMap = load_zipr_map("%s/zipr.map" % oracleZaflDir)
	oracleZaxMap  = load_zax_map("%s/zax.map" % oracleZaflDir)
	tracerZaxMap  = load_zax_map("%s/zax.map" % tracerZaflDir)
	oracleCebMap  = load_ceb_map("%s/ceb.map" % oracleZaflDir)
	tracerCebMap  = load_ceb_map("%s/ceb.map" % tracerZaflDir)

	mapStdBlocks  = map_standard_blocks()
	mapCritSplit  = map_critedge_split()
	mapCritJmpMis = map_critedge_jmpmis()

	outMap = mapStdBlocks + mapCritSplit + mapCritJmpMis

	# Write and save to disk.

	outMapFile.write("# TRACE_ID, BLOCK_ADDR, MOD_ADDR, MOD_LEN, MOD_BYTES\n")
	outMapSet = sorted(set([(ent.bbid, ent.addr, ent.modAddr, \
		ent.modLen, ent.modBytes) for ent in outMap]))
	for ent in outMapSet:
		outMapFile.write("%s, %s, %s, %s, %s\n" % (ent[0], ent[1], ent[2], ent[3], ent[4]))

	outMapFile.close()
	outLogFile.close()

if __name__ == "__main__":
	main()

