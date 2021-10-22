#include "util.h"
#include "engine_jr.h"
#include "host.h"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>

int main()
{
	// Run init funcs
	for (const InitFunctionReg *ifr = InitFunctionReg::s_pFirst; ifr; ifr = ifr->pNext)
	{
		ifr->func();
	}

	// Signal ready for requests
	hostWriteMsg(makeIdent("RDYQ"), 0, nullptr);

	while (true)
	{
		// Wait for input
		uint32_t request_ident, request_len;
		void *request_data;
		hostReadMsg(&request_ident, &request_len, &request_data);

		if (request_ident != makeIdent("REQQ"))
		{
			OC_ERR("invalid request msg\n");
		}

		// Run the request
		processRequest((char *)request_data);
		free(request_data);
		
		// Signal completion
		hostWriteMsg(makeIdent("REQA"), 0, nullptr);
	}
}