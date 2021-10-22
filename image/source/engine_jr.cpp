#include "engine_jr.h"
#include "util.h"
#include "host.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>

int hostGetNumber(int uid0, int uid1, int idx)
{
	struct __attribute__((__packed__))
	{
		int32_t uid0;
		int32_t uid1;
		int32_t idx;
	} getn_buffer;
	getn_buffer.uid0 = uid0;
	getn_buffer.uid1 = uid1;
	getn_buffer.idx = idx;
	hostWriteMsg(makeIdent("GTNQ"), sizeof(getn_buffer), &getn_buffer);

	// Read response
	uint32_t answer_ident;
	uint32_t answer_len;
	void *answer_data;
	hostReadMsg(&answer_ident, &answer_len, &answer_data);
	if (answer_ident != makeIdent("GTNA") || answer_len != sizeof(int32_t))
	{
		OC_ERR("hostGetNumber failure");
		return 0;
	}

	return *(int32_t *)answer_data;
}

void hostSetNumber(int uid0, int uid1, int idx, int val)
{
	struct __attribute__((__packed__))
	{
		int32_t uid0;
		int32_t uid1;
		int32_t idx;
		int32_t val;
	} setn_buffer;
	setn_buffer.uid0 = uid0;
	setn_buffer.uid1 = uid1;
	setn_buffer.idx = idx;
	setn_buffer.val = val;
	hostWriteMsg(makeIdent("STNQ"), sizeof(setn_buffer), &setn_buffer);
}

void hostLockNumber(int uid0, int uid1, int idx)
{
	struct __attribute__((__packed__))
	{
		int32_t uid0;
		int32_t uid1;
		int32_t idx;
	} lockn_buffer;
	lockn_buffer.uid0 = uid0;
	lockn_buffer.uid1 = uid1;
	lockn_buffer.idx = idx;
	hostWriteMsg(makeIdent("LKNQ"), sizeof(lockn_buffer), &lockn_buffer);
}

void hostPrint(const char *text)
{
	hostWriteMsg(makeIdent("PRTQ"), strlen(text), text);
}

void hostPrintNum(int num)
{
	char buffer[128];
	snprintf(buffer, OC_ARRAYSIZE(buffer), "%d", num);
	buffer[OC_ARRAYSIZE(buffer) - 1] = '\0';
	hostPrint(buffer);
}

//__attribute__((noreturn))
void hostComplete()
{
	// Signal completion
	hostWriteMsg(makeIdent("REQA"), 0, nullptr);
	OC_HANG();
}

constexpr int kStackSize = 256;

void boundsCheck(int top, int req_used)
{
	int req_free = 1;
	// SIC: Should be top instead of req_used on the second check
	if (top < req_used || req_used > kStackSize - req_free)
	{
		hostPrint("error: stack bounds fail");
		hostComplete();
	}
}

void processRequest(char *text)
{
	OC_LOG("request: %s\n", text);

	char *text_end = text + strlen(text);

	int stack[kStackSize];
	int top = 0;

	int uid0 = 0;
	int uid1 = 0;

	#define REQUIRE_STACK(n) \
		boundsCheck(top, n)

	// main interpreter loop
	char *p = text;
	while (p < text_end)
	{
		// skip whitespace
		if (*p == ' ')
		{
			++p;
			continue;
		}

		char *end = strchr(p, ' ');
		if (!end)
			end = text_end;
		*end = '\0'; // null terminate

		OC_LOG("cmd: %s\n", p);
		
		if (!strcmp(p, "user"))
		{
			REQUIRE_STACK(4);
			int req_uid0 = stack[--top];
			int req_uid1 = stack[--top];
			int req_key0 = stack[--top];
			int req_key1 = stack[--top];

			const int kKey0Idx = 0x20000000;
			const int kKey1Idx = 0x20000001;

			int actual_key0 = hostGetNumber(req_uid0, req_uid1, kKey0Idx);
			int actual_key1 = hostGetNumber(req_uid0, req_uid1, kKey1Idx);

			bool registered = (actual_key0 != 0)        | (actual_key1 != 0);
			bool matching   = (actual_key0 == req_key0) & (actual_key1 == req_key1);

			if (!registered || matching)
			{
				// valid code
				uid0 = req_uid0;
				uid1 = req_uid1;

				if (!registered)
				{
					// free account, register
					hostSetNumber(req_uid0, req_uid1, kKey0Idx, req_key0);
					hostSetNumber(req_uid0, req_uid1, kKey1Idx, req_key1);
				}
			}
			else
			{
				hostPrint("warning: wrong key, uid unchanged");
			}
		}
		else if (!strcmp(p, "getn"))
		{
			REQUIRE_STACK(1);
			int idx = stack[--top];
			stack[top++] = hostGetNumber(uid0, uid1, idx);
		}
		else if (!strcmp(p, "setn"))
		{
			REQUIRE_STACK(2);
			int idx = stack[--top];
			int val = stack[--top];
			hostSetNumber(uid0, uid1, idx, val);
		}
		else if (!strcmp(p, "lockn"))
		{
			REQUIRE_STACK(1);
			int idx = stack[--top];
			hostLockNumber(uid0, uid1, idx);
		}
		else if (!strcmp(p, "help"))
		{
			REQUIRE_STACK(0);
			hostPrint("enter commands on one line separated by spaces.");
			hostPrint("");
			hostPrint("example:");
			hostPrint("4 3 2 1 user 5 6 + 5 setn 5 getn print");
			hostPrint("");
			hostPrint("available commands:");
			hostPrint("help      : print this listing");
			hostPrint("user      : login/register as user");
			hostPrint("getn      : get saved number");
			hostPrint("setn      : set saved number");
			hostPrint("lockn     : lock saved number from writing");
			hostPrint("+         : add two numbers");
			hostPrint("-         : subtract two numbers");
			hostPrint("*         : multiply two numbers");
			hostPrint("~         : delete number");
			hostPrint("<integer> : push number to stack");
			hostPrint("!         : print number");
		}
		else if (!strcmp(p, "!"))
		{
			REQUIRE_STACK(1);
			hostPrintNum(stack[top - 1]);
		}
		else if (!strcmp(p, "+")) // add
		{
			REQUIRE_STACK(2);
			int rhs = stack[--top];
			int lhs = stack[--top];
			stack[top++] = lhs + rhs;
		}
		else if (!strcmp(p, "-"))
		{
			REQUIRE_STACK(2);
			int rhs = stack[--top];
			int lhs = stack[--top];
			stack[top++] = lhs - rhs;
		}
		else if (!strcmp(p, "*"))
		{
			REQUIRE_STACK(2);
			int rhs = stack[--top];
			int lhs = stack[--top];
			stack[top++] = lhs * rhs;
		}
		else if (!strcmp(p, "~"))
		{
			REQUIRE_STACK(1);
			--top;
		}
		else if (isdigit(*p) || *p == '+' || *p == '-') // push constant
		{
			REQUIRE_STACK(0);
			stack[top++] = atoi(p);
		}
		else
		{
			hostPrint("error: unknown command");
			hostComplete();
		}

		p = end + 1;
	}

	// Finished normally.
	// Let outer handle complete so that return address overwrite works.
}