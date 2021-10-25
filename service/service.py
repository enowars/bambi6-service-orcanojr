#!/usr/bin/env python3

import sys
import os
import struct
import string
import datetime
import asyncio

import traceback
import subprocess

SERVICE_PORT = 53273
QUEUE_MAX_LEN = 64
DOLPHIN_PATH = os.getenv("DOLPHIN_EMU_NOGUI")
IMAGE_PATH = "./image.elf"
DATA_DIR = "/data"
WORKER_COUNT = 2
WORKER_MAX_REQUESTS = 1 # how many requests a worker can handle before restart
DATA_CLEANUP_EXPIRY_TIME = 15 * 60 # 15 minutes ~= 1 min/round * 10 rounds + margin
DATA_CLEANUP_CYCLE_TIME = 5 * 60 # guarantees max age 20 minutes
LOG_DEBUG = True

MAX_REQUEST_SIZE = 1024 # maximum size for request to be passed into Dolphin
MAX_REQUEST_TIME = 0.25
DOL_TIMEOUT = 2.0 # timeout for comms with Dolphin before abort & restart
DOL_STARTUP_TIME = 10.0 # how long to wait for Dolphin to start up in seconds
DOL_STARTUP_INTERVAL = 0.05 # wait time between successive attempts to get to Dolphin

def log_debug(text):
	if LOG_DEBUG:
		print(text)

async def imm_error(t):
	try:
		await t
	except:
		print("Task {} failed with traceback:".format(t))
		traceback.print_exc()

class OrcanoFrontend:
	async def handle_cleanup(self):
		while True:
			# Work before sleep so we do it at startup
			print("Beginning periodic data cleanup...")
			scan_time = datetime.datetime.now(datetime.timezone.utc)
			total_count = 0
			deleted_count = 0
			error_count = 0
			files = []
			with os.scandir(DATA_DIR) as it:
				for de in it:
					# Give other stuff a chance to run since we might have to
					# process a large amount of files
					await asyncio.sleep(0)

					# Skip irrelevant stuff
					if not de.is_file():
						continue
					if de.name.startswith("."):
						continue

					total_count += 1

					de_stat = de.stat()
					de_mtime = datetime.datetime.fromtimestamp(de_stat.st_mtime, tz=datetime.timezone.utc)
					if scan_time - de_mtime >= datetime.timedelta(seconds=DATA_CLEANUP_EXPIRY_TIME):
						# Delete
						try:
							# print("Deleting {} (mtime={}, stime={})".format(de.path, de_mtime, scan_time))
							os.remove(de.path)
							deleted_count += 1
						except OSError:
							print("Data cleanup failed to delete {}, traceback:".format(de.path))
							traceback.print_exc()
							error_count += 1

			end_time = datetime.datetime.now(datetime.timezone.utc)
			print("Data cleanup finished in {:.3f} seconds.".format((end_time - scan_time).total_seconds()))
			print("Data cleanup stats: total {}, deleted {}, errors {}, remaining {}".format(
				total_count,
				deleted_count,
				error_count,
				total_count - deleted_count
			))

			# Wait for next cycle
			await asyncio.sleep(DATA_CLEANUP_CYCLE_TIME)

	async def handle_workers(self):
		workers = []
		while True:
			while len(workers) < WORKER_COUNT:
				workers.append(asyncio.create_task(self.handle_dolphin()))
			done, pending = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
			for d in done: # Trigger exceptions
				try:
					await d
				except:
					traceback.print_exc()
			print("Workers: {} died".format(len(done)))
			workers = list(pending)

	async def start_dolphin(self):
		inst = {}
		inst["dol_port"] = await self.port_pool.get()
		inst["dol_proc"] = await asyncio.create_subprocess_exec(
			#"strace",
			DOLPHIN_PATH,
			"-e", IMAGE_PATH,
			"-p", "headless",
			"-v", "Null", # Disable video
			"-C", "Dolphin.Core.GeckoPort={}".format(inst["dol_port"]),
			#stderr=subprocess.PIPE,
			stdout=subprocess.PIPE
		)

		async def runner(inst):
			stdout_data, stderr_data = await inst["dol_proc"].communicate()
			inst["dol_fut"].set_result((stdout_data, stderr_data))
			await self.port_pool.put(inst["dol_port"])

			print("Dolphin ended, port={}, code={}".format(inst["dol_port"], inst["dol_proc"].returncode), flush=True)
			print("stdout:")
			print(stdout_data)
			print("stderr:")
			print(stderr_data)

		# Start the waiter task
		inst["dol_fut"] = asyncio.Future()
		asyncio.create_task(runner(inst))

		# Open conn to USB Gecko port
		connect_fail = True
		tries = int(DOL_STARTUP_TIME / DOL_STARTUP_INTERVAL)
		p = inst["dol_port"]
		for i in range(tries):
			try:
				inst["dol_rx"], inst["dol_tx"] = await asyncio.open_connection("127.0.0.1", p)
				print("Dolphin connected on port {}".format(p))
				connect_fail = False
				break
			except ConnectionRefusedError:
				pass

			if inst["dol_fut"].done():
				print("Dolphin died before connection could be established, port={}".format(inst["dol_port"]))
				break

			print("Dolphin connection failed, retrying ({})...".format(i))
			await asyncio.sleep(DOL_STARTUP_INTERVAL)

		if connect_fail:
			raise ConnectionRefusedError

		print("Dolphin started, port={}, pid={}".format(inst["dol_port"], inst["dol_proc"].pid))

		# Wait for ready
		rdy_msg = await inst["dol_rx"].readexactly(4 + 4)
		if rdy_msg != b"RDYQ\x00\x00\x00\x00":
			raise ConnectionRefusedError

		print("Dolphin ready, port={}, pid={}".format(inst["dol_port"], inst["dol_proc"].pid))

		return inst

	async def stop_dolphin(self, inst):
		# Clean up process
		print("Stopping Dolphin...")
		inst["dol_proc"].kill()
		await inst["dol_proc"].wait()

		inst["dol_tx"].close()
		# Waiting apparently can throw ConnectionResetError if the connection is remotely terminated
		# await inst["dol_tx"].wait_closed()

	async def handle_dolphin(self):
		# Start Dolphin
		inst = await self.start_dolphin()

		async def dol_write_msg(ident, data):
			msg_buffer = bytearray(4 + 4 + len(data))
			msg_buffer[0:4] = ident
			msg_buffer[4:8] = struct.pack(">L", len(data))
			msg_buffer[8:] = data
			log_debug("Send msg: {}".format(msg_buffer))
			inst["dol_tx"].write(msg_buffer)
			await inst["dol_tx"].drain()

		async def dol_read_msg():
			msg_header = await inst["dol_rx"].readexactly(4 + 4)
			ident = msg_header[0:4]
			size = struct.unpack(">L", msg_header[4:8])[0]
			data = await inst["dol_rx"].readexactly(size)
			log_debug("Recv msg: {}".format(msg_header + data))
			return ident, data

		async def dol_timeout(coro):
			# With global timeout, this is unnecessary
			#return await asyncio.wait_for(coro, DOL_TIMEOUT)
			return await coro

		class DolphinCommunicationError(Exception): pass

		async def process_request(task):
			# Send the initial request
			await dol_timeout(dol_write_msg(b"REQQ", task["data"] + b"\x00"))

			# Respond to queries
			result = bytearray()
			while True:
				ident, data = await dol_timeout(dol_read_msg())
				if ident == b"REQA":
					break
				elif ident == b"GTNQ":
					if len(data) != 0xc:
						raise DolphinCommunicationError("invalid getn query len 0x{:x}".format(len(data)))

					uid = struct.unpack_from(">Q", data, 0x0)[0]
					idx = struct.unpack_from(">L", data, 0x8)[0]

					# TODO: Should we check that this user exists here?
					num_path = os.path.join(DATA_DIR, "num_{:016x}_{:08x}".format(uid, idx))
					num_data = None
					try:
						with open(num_path, "rb") as f:
							num_data = f.read()
						if len(num_data) != 4:
							print("Invalid number data read from disk for uid={:016x}, idx={:08x}".format(uid, idx))
							num_data = None
					except FileNotFoundError:
						num_data = None

					# Provide default
					if num_data == None:
						num_data = b"\x00\x00\x00\x00"

					await dol_timeout(dol_write_msg(b"GTNA", num_data))
				elif ident == b"STNQ":
					if len(data) != 0x10:
						raise DolphinCommunicationError("invalid setn query len 0x{:x}".format(len(data)))

					uid = struct.unpack_from(">Q", data, 0x0)[0]
					idx = struct.unpack_from(">L", data, 0x8)[0]
					num_data = data[0xc:0x10]
					
					# Protect anonymous user
					if uid == 0 and (idx == 0x20000000 or idx == 0x20000001):
						continue

					# Check for lock
					lock_path = os.path.join(DATA_DIR, "lock_{:016x}_{:08x}".format(uid, idx))
					try:
						with open(lock_path, "rb") as f:
							locked = True
					except FileNotFoundError:
						locked = False

					# TODO: This shares code with GTNQ, maybe we can extract it.
					if not locked:
						num_path = os.path.join(DATA_DIR, "num_{:016x}_{:08x}".format(uid, idx))
						with open(num_path, "wb") as f:
							f.write(num_data)
				elif ident == b"LKNQ":
					if len(data) != 0xc:
						raise DolphinCommunicationError("invalid lockn query len 0x{:x}".format(len(data)))

					uid = struct.unpack_from(">Q", data, 0x0)[0]
					idx = struct.unpack_from(">L", data, 0x8)[0]

					# Cannot lock numbers on anonymous account
					if uid == 0:
						continue

					# TODO: This shares code with STNQ
					lock_path = os.path.join(DATA_DIR, "lock_{:016x}_{:08x}".format(uid, idx))

					# Create the lock file if it didn't exist already
					with open(lock_path, "wb") as f:
						pass
				elif ident == b"PRTQ":
					result += bytes(filter(lambda c: c in string.printable.encode(), data))
					result += b"\n"
				elif ident == b"LOGQ":
					print("DOL log: {}".format(data))
				elif ident == b"ERRQ":
					print("DOL reported error: {}".format(data))
					raise DolphinCommunicationError()
				else:
					print("DOL bad msg: ident={} data={}".format(ident, data))
					raise DolphinCommunicationError()

			return result

		# Serve requests
		for request_index in range(WORKER_MAX_REQUESTS):
			task = await self.request_queue.get()

			request_start = datetime.datetime.utcnow()
			print("Serving request to Dolphin on port {}: {}".format(inst["dol_port"], bytes(task["data"])))
			try:
				result = await asyncio.wait_for(process_request(task), MAX_REQUEST_TIME)
			except (asyncio.IncompleteReadError, asyncio.TimeoutError, DolphinCommunicationError) as ex:
				# Dolphin died or timed out
				print("Request execution failed, traceback:")
				traceback.print_exc()

				# Restart Dolphin
				await self.stop_dolphin(inst)

				# If not last request, restart
				if request_index < WORKER_MAX_REQUESTS - 1:
					print("Shutdown complete, starting...")
					inst = await self.start_dolphin()
					print("Restart complete.")
				else:
					print("Last request, no restart")

				# Fail the request
				if isinstance(ex, asyncio.TimeoutError):
					result = b"error: timeout\n"
				else:
					result = b"error: internal\n"

			# For performance estimation
			# TODO: Should probably get rid of this overhead for final
			request_end = datetime.datetime.utcnow()
			request_duration = request_end - request_start
			print("Request took {}us: {}".format(request_duration / datetime.timedelta(microseconds=1), bytes(result)))

			# Return the result
			task["result_fut"].set_result(result)
			self.request_queue.task_done()

		# Kill our instance on the way out
		await self.stop_dolphin(inst)

	async def handle_connection(self, client_rx, client_tx):
		client_tx.write(b"Hey! Listen!\n")
		await client_tx.drain()

		# TODO: Network timeouts?
		try:
			while True:
				client_tx.write(b"> ")
				await client_tx.drain()
				line = await client_rx.readuntil(b"\n")

				# Assemble our request
				task_data = line.strip()

				# Limit request size
				if len(task_data) > MAX_REQUEST_SIZE:
					client_tx.write(b"request too large\n")
					continue

				# Exit upon empty line
				if not task_data:
					break

				# Assemble request
				task_result_fut = asyncio.Future()
				task = {
					"data": task_data,
					"result_fut": task_result_fut
				}

				# Submit for processing
				await self.request_queue.put(task)

				# Wait for completion
				result = await task_result_fut

				# Write back the result
				client_tx.write(result)
		except (asyncio.IncompleteReadError, asyncio.TimeoutError):
			pass

		client_tx.close()
		await client_tx.wait_closed()

	async def run(self):
		self.port_pool = asyncio.Queue()
		for i in range(55020, 55520):
			await self.port_pool.put(i)
		self.request_queue = asyncio.Queue(maxsize=QUEUE_MAX_LEN)
		asyncio.create_task(imm_error(self.handle_workers()))
		asyncio.create_task(imm_error(self.handle_cleanup()))
		server = await asyncio.start_server(self.handle_connection, "0.0.0.0", SERVICE_PORT)
		print("Serving requests on {}".format(SERVICE_PORT))
		await server.serve_forever()

async def main():
	fe = OrcanoFrontend()
	await fe.run()

if __name__ == "__main__":
	asyncio.run(main())
