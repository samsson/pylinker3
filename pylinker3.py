
#!/usr/bin/python
import sys, struct, datetime, binascii, argparse, math, os
from pylinker3_lists import flag_hash, file_hash, show_wnd_hash, vol_type_hash, hotkey_hash

hide_string = 255 * " "
cmdline_string = ''
editcommandline = False
apimode = None
output = ""

# argparser
parser = argparse.ArgumentParser(description='Parse and modify Microsoft .LNK files')
parser.add_argument("-f", "--file", metavar='file', required=False, help="Input .lnk file")
parser.add_argument("-c", "--cmdline", metavar='cmdline', required=False, help="Set a new cmdline for the .lnk file")
parser.add_argument("--hide", option_strings=[], dest='hide', nargs='?', const=True, default=False, type=None, choices=None, help="Will hide the commandline from plain view if observed from explorer")
parser.add_argument("-o", "--output", metavar='output', required=False, default=False, help="Define output file. Default is inputfilename[0-9].lnk")
args = parser.parse_args()

def FormatOutput(string):

	global output
	if apimode == True:
		output.append(string)

	else:
		output += string

	return

def hotkeytranslate(hotkey_hex):

	LowByte = hotkey_hash[int(hotkey_hex[-2:], 16)]
	HighByte = hotkey_hash[int(hotkey_hex[:2], 16)]
	return HighByte + LowByte

def write_custom_commandline(file_part_1, file_part_2, output, new_bytes):

	# Create a copy with modified commandline
	filename = args.file.split(".")
	#newfilename = ""
	if args.output == False:
		for i in range(10):
			newfilename = filename[0] + str(i) + ".lnk"
			if not os.path.isfile(newfilename):
				break
			if i == 9:
				FormatOutput(" [!] Error: Unable to create copy file\n")
				sys.exit(1)

		f2 = open(newfilename,"w+b")
	else:
		f2 = open(args.output,"w+b")

	f2.write(file_part_1)

	# Check hide option and calculate cmdline size accordingly
	if args.hide == True:
		lenght = len(cmdline_string) + 255
	else:
		lenght = len(cmdline_string)

	byte_array = number_to_bytes(lenght)

	# Write cmdline argument size in beginning of cmdline section
	if int(lenght) > int(0xff):
		if int(lenght) > int(0xffff):
			FormatOutput(" [!] Error: Cmdline bigger than 0xFFFF, unable to write\n")
			sys.exit(1)

		f2.write(bytes([c for t in zip(byte_array[1::2], byte_array[::2]) for c in t]))

		if args.hide == True:
			for i in hide_string:
				f2.write(bytes(i, 'utf8'))
				f2.write(bytes("\0", 'utf8'))

		#write commandline argument with null bytes
		for i in cmdline_string:
			f2.write(bytes(i, 'utf8'))
			f2.write(bytes("\0", 'utf8'))

		#add terminating null
		f2.write(bytes("\0\0", 'utf8'))
	else:
		f2.write(byte_array)
		if args.hide == True:
			for i in hide_string:
				f2.write(bytes("\0", 'utf8'))
				f2.write(bytes(i, 'utf8'))

		#write commandline argument with null bytes
		for i in cmdline_string:
			f2.write(bytes("\0", 'utf8'))
			f2.write(bytes(i, 'utf8'))

		#add terminating null
		f2.write(bytes("\0\0\0", 'utf8'))

	# Complete with the saved second part.
	f2.write(file_part_2)

	if new_bytes != "":
		f2.seek(20)
		f2.write(bytes.fromhex(new_bytes))
		#f2.write(bytes(new_bytes, 'utf8'))

def number_to_bytes(number):
	nibble_count = int(math.log(number, 256)) + 1
	hex_string = '{:0{}x}'.format(number, nibble_count * 2)
	return bytearray.fromhex(hex_string)

def reverse_hex(HEXDATE):
	hexVals = [HEXDATE[i:i + 2] for i in range(0, 16, 2)]
	reversedHexVals = hexVals[::-1]
	return ''.join(reversedHexVals)

def assert_lnk_signature(f):
	f.seek(0)
	sig = f.read(4)
	guid = f.read(16)
	if sig.hex() != '4c000000':
		raise Exception("This is not a .lnk file.")
	if guid.hex() != '0114020000000000c000000000000046':
		raise Exception("Cannot read this kind of .lnk file.")

# read COUNT bytes at LOC and unpack into binary
def read_unpack_bin(f, loc, count):

	# jump to the specified location
	f.seek(loc)
	raw = f.read(count)
	result = ""
	for b in raw:
		result += format(b, '08b')[::-1]
	return result

# read COUNT bytes at LOC and unpack into ascii
def read_unpack_ascii(f,loc,count):
	# jump to the specified location
	f.seek(loc)
	# should interpret as ascii automagically
	return f.read(count)

# read COUNT bytes at LOC
def read_unpack(f, loc, count):
	# jump to the specified location
	f.seek(loc)
	raw = f.read(count)
	result = ""
	for b in raw:
		result += binascii.hexlify(bytes([b])).decode("utf-8")
	return result

# Read a null terminated string from the specified location.
def read_null_term(f, loc):
	# jump to the start position
	f.seek(loc)
	result = ""
	b = f.read(1)
	while b.hex() != "00":
		result += b.decode("utf-8")
		b = f.read(1)
	return result

# adapted from pylink.py
def ms_time_to_unix_str(windows_time):
	time_str = ''
	try:
		unix_time = windows_time / 10000000.0 - 11644473600
		time_str = str(datetime.datetime.fromtimestamp(unix_time))
	except:
		pass
	return time_str

def add_info(f,loc):
	tmp_len_hex = reverse_hex(read_unpack(f,loc,2))
	#print(tmp_len_hex)
	tmp_len = 2 * int(tmp_len_hex, 16)
	#print(tmp_len)
	loc += 2
	if (tmp_len != 0):
		tmp_string = read_unpack_ascii(f, loc, tmp_len)
		now_loc = f.tell()
		return (tmp_string, now_loc)
	else:
		now_loc = f.tell()
		return (None, now_loc)

def parse_lnk(filename):

	output = ""
	new_bytes = ""

	#read the file in binary module
	try:
		f = open(filename, "r+b")
	except Exception as e:
		return "[!] Exception: "+str(e)

	try:
		assert_lnk_signature(f)
	except Exception as e:
		return "[!] Exception: "+str(e)

	FormatOutput("\nLnk File: " + filename + "\n")
	# get the flag bits´
	flags = read_unpack_bin(f,20,4)
	flag_desc = list()

	for cnt in range(len(flags)-1):
		bit = int(flags[cnt])
		# grab the description for this bit
		flag_desc.append(flag_hash[cnt][bit])

	flag_desc_new = list()
	for i in flag_desc:
		if i != '':
			flag_desc_new.append(i)
	FormatOutput("Link Flags: " + ":".join(flag_desc_new) + "\n")

	# File Attributes 4bytes@18h = 24d
	file_attrib = read_unpack_bin(f,24,4)
	attrib_desc = list()
	for cnt in range(0, 14):
		bit = int(file_attrib[cnt])
		# grab the description for this bit
		if bit == 1:
			attrib_desc.append(file_hash[cnt][1])
	if len(attrib_desc) > 0:
		FormatOutput("File Attributes: " + " | ".join(attrib_desc) + "\n")

	FormatOutput("\nTarget executable timestamps: \n")
	# Create time 8bytes @ 1ch = 28

	create_time = reverse_hex(read_unpack(f,28,8))
	FormatOutput("\tCreate Time:   "+ms_time_to_unix_str(int(create_time, 16)) + "\n")

	# Access time 8 bytes@ 0x24 = 36D
	access_time = reverse_hex(read_unpack(f,36,8))
	FormatOutput("\tAccess Time:   "+ms_time_to_unix_str(int(access_time, 16)) + "\n")

	# Modified Time8b @ 0x2C = 44D
	modified_time = reverse_hex(read_unpack(f,44,8))
	FormatOutput("\tModified Time: "+ms_time_to_unix_str(int(modified_time, 16)) + "\n\n")

	# Target File length starts @ 34h = 52d
	length_hex = reverse_hex(read_unpack(f,52,4))
	length = int(length_hex, 16)
	FormatOutput("Target length: "+str(length) + "\n")

	# Icon File info starts @ 38h = 56d
	icon_index_hex = reverse_hex(read_unpack(f,56,4))
	icon_index = int(icon_index_hex, 16)
	FormatOutput("Icon Index: "+str(icon_index) + "\n")

	# show windows starts @3Ch = 60d
	show_wnd_hex = reverse_hex(read_unpack(f,60,1))
	show_wnd = int(show_wnd_hex, 16)
	FormatOutput("ShowWnd: "+str(show_wnd_hash[show_wnd]) + "\n")

	# hot key starts @40h = 64d
	hotkey_hex = reverse_hex(read_unpack(f,64,2))
	if hotkey_hex == "0000":
		FormatOutput("HotKey: NO Hotkey \n")
	else:

		FormatOutput("HotKey: "+hotkeytranslate(hotkey_hex) + "\n")

	#------------------------------------------------------------------------
	# End of Flag parsing
	#------------------------------------------------------------------------

	# get the number of items
	items_hex = reverse_hex(read_unpack(f,76,2))
	items = int(items_hex, 16)
	list_end = 78 + items
	struct_start = list_end
	first_off_off = struct_start + 4
	vol_flags_off = struct_start + 8
	local_vol_off = struct_start + 12
	base_path_off = struct_start + 16
	net_vol_off = struct_start + 20
	rem_path_off = struct_start + 24

	# Structure length
	struct_len_hex = reverse_hex(read_unpack(f,struct_start,4))
	struct_len = int(struct_len_hex, 16)
	struct_end = struct_start + struct_len

	# First offset after struct - Should be 1C under normal circumstances
	first_off = read_unpack(f,first_off_off,1)

	# File location flags
	vol_flags = read_unpack_bin(f,vol_flags_off,1)

	# Local volume table
	# Random garbage if bit0 is clear in volume flags

	if vol_flags[:2] == "10":

		FormatOutput("\nTarget is on local volume\n")

		# This is the offset of the local volume table within the
		# File Info Location Structure
		loc_vol_tab_off_hex = reverse_hex(read_unpack(f,local_vol_off,4))
		loc_vol_tab_off = int(loc_vol_tab_off_hex, 16)

		# This is the asolute start location of the local volume table
		loc_vol_tab_start = loc_vol_tab_off + struct_start

		# This is the length of the local volume table
		local_vol_len_hex = reverse_hex(read_unpack(f,loc_vol_tab_off+struct_start,4))
		local_vol_len = int(local_vol_len_hex, 16)

		# We now have enough info to
		# Calculate the end of the local volume table.
		local_vol_tab_end = loc_vol_tab_start + local_vol_len

		# This is the volume type
		curr_tab_offset = loc_vol_tab_off + struct_start + 4
		vol_type_hex = reverse_hex(read_unpack(f,curr_tab_offset,4))
		vol_type = int(vol_type_hex, 16)
		FormatOutput("\tVolume Type: "+str(vol_type_hash[vol_type]) + "\n")

		# Volume Serial Number
		curr_tab_offset = loc_vol_tab_off + struct_start + 8
		vol_serial = reverse_hex(read_unpack(f,curr_tab_offset,4))
		FormatOutput("\tVolume Serial: "+vol_serial + "\n")

		# Get the location, and length of the volume label
		vol_label_loc = loc_vol_tab_off + struct_start + 16
		vol_label_len = local_vol_tab_end - vol_label_loc
		vol_label = read_unpack_ascii(f,vol_label_loc,vol_label_len)
		if vol_label == b'\x00':
			FormatOutput("\tVol Label: No Volume Label\n")
		else:
			FormatOutput("\tVol Label: "+vol_label.decode("utf-8") + "\n")

		#------------------------------------------------------------------------
		# This is the offset of the base path info within the
		# File Info structure
		#------------------------------------------------------------------------

		base_path_off_hex = reverse_hex(read_unpack(f,base_path_off,4))
		base_path_off = struct_start + int(base_path_off_hex, 16)

		# Read base path data upto NULL term
		base_path = read_null_term(f,base_path_off)
		FormatOutput("\tTarget executable path: "+base_path + "\n\n")

	# Network Volume Table

	elif vol_flags[:2] == "01":

		# TODO: test this section!
		FormatOutput("Target is on Network share\n")
		net_vol_off_hex = reverse_hex(read_unpack(f,net_vol_off,4))
		net_vol_off = struct_start + int(net_vol_off_hex, 16)
		net_vol_len_hex = reverse_hex(read_unpack(f,net_vol_off,4))
		net_vol_len = struct_start + int(net_vol_len_hex, 16)

		# Network Share Name
		net_share_name_off = net_vol_off + 8
		net_share_name_loc_hex = reverse_hex(read_unpack(f,net_share_name_off,4))
		net_share_name_loc = int(net_share_name_loc_hex, 16)

		if(net_share_name_loc != 20):
			FormatOutput(" [!] Error: NSN ofset should always be 14h\n")
			sys.exit(1)

		net_share_name_loc = net_vol_off + net_share_name_loc
		net_share_name = read_null_term(f,net_share_name_loc)
		FormatOutput("\tNetwork Share Name: "+str(net_share_name) + "\n")

		# Mapped Network Drive Info
		net_share_mdrive = net_vol_off + 12
		net_share_mdrive_hex = reverse_hex(read_unpack(f,net_share_mdrive,4))
		net_share_mdrive = int(net_share_mdrive_hex, 16)

		if(net_share_mdrive != 0):
			net_share_mdrive = net_vol_off + net_share_mdrive
			net_share_mdrive = read_null_term(f,net_share_mdrive)
			FormatOutput("\tMapped Drive: "+str(net_share_mdrive) + "\n")

	else:
		FormatOutput(" [!] Error: unknown volume flags\n")
		sys.exit(1)

	# Remaining path
	rem_path_off_hex = reverse_hex(read_unpack(f,rem_path_off,4))
	rem_path_off = struct_start +int(rem_path_off_hex, 16)
	rem_data = read_null_term(f,rem_path_off);
	FormatOutput("(App Path:) Remaining Path: "+str(rem_data) + "\n")

	#------------------------------------------------------------------------
	# End of FileInfo Structure
	#------------------------------------------------------------------------

	# The next starting location is the end of the structure
	next_loc = struct_end
	addnl_text = ""

	if flags[2]=="1":
		 addnl_text,next_loc = add_info(f,next_loc)
		 FormatOutput("Description: "+str(addnl_text) + "\n")

	if flags[3]=="1":
		 addnl_text,next_loc = add_info(f,next_loc)
		 FormatOutput("Relative Path: "+str(addnl_text.decode('utf-16le', errors='ignore')) + "\n")

	if flags[4]=="1":
		 addnl_text,next_loc = add_info(f,next_loc)
		 FormatOutput("Working Dir: "+addnl_text.decode('utf-16le', errors='ignore') + "\n")

	# Check if there is willingness to modify commandline but no commandline is present.
	if flags[5]=="0" and editcommandline == True:

		#
		flags_new = flags[:8][:5] + "1" + flags[:8][-2:]
		new_bytes = hex(int(flags_new[::-1], 2)).lstrip("0x")
		flags = flags_new + flags[8:]
		#sys.exit()

	if flags[5]=="1":

		# Check if commandline needs editing
		if editcommandline == True:
			# Save beginning of file before commandline section
			f.seek(0)
			file_part_1 = f.read(next_loc)
			addnl_text,next_loc = add_info(f,next_loc)
			FormatOutput("Command Line: "+str(addnl_text.decode('utf-16le', errors='ignore')) + "\n")

			# Save rest of the file after commandline section
			f.seek(next_loc)
			file_part_2 = f.read()
			write_custom_commandline(file_part_1, file_part_2, output, new_bytes)

		# Else just add info
		else:
			addnl_text,next_loc = add_info(f,next_loc)
			FormatOutput("Command Line: "+str(addnl_text.decode('utf-16le', errors='ignore').lstrip(" ")) + "\n")

	if flags[6]=="1":
		 addnl_text,next_loc = add_info(f,next_loc)
		 FormatOutput("Icon filename: "+str(addnl_text.decode('utf-16le', errors='ignore')) + "\n")

	return

if __name__ == "__main__":

	if args.file != None:

		if args.cmdline != None:

			editcommandline = True
			cmdline_string = args.cmdline
			parse_lnk(args.file)
			print("File modified! ")

		else:
			parse_lnk(args.file)
			print("out: ",output)
	else:
		print("Missing Input File")

if __name__ == "pylinker3":

	if args.cmdline != None:
		sys.exit()

	def parse(filename):
		global output
		global apimode
		output = []
		apimode = True
		parse_lnk(filename)
		return output
