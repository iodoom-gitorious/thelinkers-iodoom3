/*
	messages.c

	Message management for tremmaster

	Copyright (C) 2004  Mathieu Olivier

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
/*
 * Ported to iodoom3
 *
 * Copyright (C) 2012 Axel Bayerl
 *
 * */

#include "common.h"
#include "messages.h"
#include "servers.h"


// ---------- Constants ---------- //

// Timeouts (in secondes)
#define TIMEOUT_HEARTBEAT		2
#define TIMEOUT_INFORESPONSE	(15 * 60)

// Period of validity for a challenge string (in secondes)
#define TIMEOUT_CHALLENGE 2

// Maximum size of a reponse packet
#define MAX_PACKET_SIZE 1400


// Types of messages (with samples):

// "heartbeat\0"
#define S2M_HEARTBEAT "heartbeat" //OK

// "getinfo A_Challenge"
#define M2S_GETINFO "getInfo" //OK

// "infoResponse\n\\pure\\1\\..."
#define S2M_INFORESPONSE "infoResponse" //OK

// "getServers|Version|fs_game|filterFlags|"
#define C2M_GETSERVERS "getServers"

// "servers\0(<ip><port>)*"
#define M2C_GETSERVERSREPONSE "servers"

// "clAuth"
#define C2M_CLAUTH "clAuth"

// "clAuth"
#define C2M_GAMEAUTH "gameAuth"

// "authKey"
#define M2C_AUTHKEY "authKey"
#define M2C_AUTHKEY_LEN_OK 23

// ---------- Private functions ---------- //

/*
====================
SearchInfostring

Search an infostring for the value of a key
====================
*/
static char* SearchInfostring (const char* infostring, const char* key)
{
	static char value [256];
	char crt_key [256];
	char c;

	//value_ind = 0;
	for (;;)
	{

		if (infostring[0] == '\0' && infostring[0] == '\0') return NULL;

		strncpy(crt_key, infostring, sizeof(crt_key));
		infostring += strlen(infostring) + 1;

		// If it's the key we are looking for, save it in "value"
		if (!strcmp (crt_key, key))
		{
			memcpy(value, infostring, MIN(sizeof(value)-1, strlen(infostring)) + 1);
			value[sizeof(value)-1] = '\0';
			return value;
		}

		// Else, skip the value
		for (;;)
		{
			c = *infostring++;

			if (c == '\0')
				break;
		}
	}
}

/*
====================
BuildChallenge

Build a challenge for a "getinfo" message
====================
*/
static const int32_t BuildChallenge (void)
{
	int32_t challenge;
	size_t ind;

	for (ind = 0; ind < sizeof(challenge); ind++)
	{
		char c;
		do
		{
			c = 33 + rand () % (126 - 33 + 1);  // -> c = 33..126
		} while (c == '\\' || c == ';' || c == '"' || c == '%' || c == '/');

		((unsigned char*)&challenge)[ind] = c;
	}

	return challenge;
}


/*
====================
SendGetInfo

Send a "getInfo" message to a server
====================
*/
static void SendGetInfo (server_t* server)
{
	char msg [64] = "\xFF\xFF" M2S_GETINFO;

	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		server->challenge = BuildChallenge ();
		server->challenge_timeout = crt_time + TIMEOUT_CHALLENGE;
	}

//	strncat (msg, server->challenge, sizeof (msg) - strlen (msg));
	memcpy (msg + strlen (msg) + 1, &(server->challenge), sizeof(server->challenge));
	sendto (outSock, msg, strlen (msg) + 1 + sizeof(server->challenge), 0,
			(const struct sockaddr*)&server->address,
			sizeof (server->address));

	MsgPrint (MSG_DEBUG, "%s <--- getInfo with challenge \"0x%x\"\n",
			  peer_address, server->challenge);
}


/*
====================
HandleGetServers

Parse getservers requests and send the appropriate response

Flags:
	Password protected:
		Any :	   0x00
		Pass Only : 0x01
		Hide Pass : 0x02
	Players:
		Any :	   0x00
		Hide Full : 0x04
		Hide Both : 0x08
	GameType:
		Any :	   0x00
		DM :		0x10
		Tourney :   0x20
		Team DM :   0x30
		Last Man :  0x00 //Overflow?
		CTF :	   0x10 //  "  "
====================
*/
static void HandleGetServers (const char* msg, const struct sockaddr_in* addr)
{
	const char* packetheader = "\xFF\xFF" M2C_GETSERVERSREPONSE;
	const size_t headersize = strlen (packetheader) + 1;
	char packet [MAX_PACKET_SIZE];
	size_t packetind;
	server_t* sv;
	uint32_t protocol;
	unsigned int sv_addr;
	unsigned short sv_port;
	char flags;
	qboolean no_empty;
	qboolean no_full;
	unsigned int numServers = 0;

	memcpy (&protocol, msg, sizeof(protocol));
	msg += sizeof(protocol);

	MsgPrint (MSG_DEBUG, "%s ---> getservers( protocol version %d.%d )\n",
			peer_address, PROTOCOL_MAJOR(protocol), PROTOCOL_MINOR(protocol));

	msg+=strlen(msg)+1;
	memcpy (&flags, msg, sizeof(flags));

	no_empty = flags & 0x08;
	no_full = (flags & 0x04) | (flags & 0x08);

	// Initialize the packet contents with the header
	packetind = headersize;
	memcpy(packet, packetheader, headersize);

	// Add every relevant server
	for (sv = Sv_GetFirst (); /* see below */;  sv = Sv_GetNext ())
	{
		// If we're done, or if the packet is full, send the packet
		if (sv == NULL || packetind > sizeof (packet) - 6)
		{
			// Send the packet to the client
			sendto (inSock, packet, packetind, 0, (const struct sockaddr*)addr,
					sizeof (*addr));

			MsgPrint (MSG_DEBUG, "%s <--- servers (%u servers)\n",
						peer_address, numServers);

			// If we're done
			if (sv == NULL)
				return;
			
			// Reset the packet index (no need to change the header)
			packetind = headersize;
		}

		sv_addr = ntohl (sv->address.sin_addr.s_addr);
		sv_port = ntohs (sv->address.sin_port);

		// Extra debugging info
		if (max_msg_level >= MSG_DEBUG)
		{
			MsgPrint (MSG_DEBUG,
					  "Comparing server: IP:\"%u.%u.%u.%u:%hu\", p:%u.%u, c:%hu\n",
					  sv_addr >> 24, (sv_addr >> 16) & 0xFF,
					  (sv_addr >>  8) & 0xFF, sv_addr & 0xFF,
					  sv_port, PROTOCOL_MAJOR(sv->protocol), PROTOCOL_MINOR(sv->protocol),
					  sv->nbclients );

			if (sv->protocol != protocol)
				MsgPrint (MSG_DEBUG,
						  "Reject: protocol %u != requested %u\n",
						  sv->protocol, protocol);
			if (sv->nbclients == 0 && no_empty)
				MsgPrint (MSG_DEBUG,
						  "Reject: nbclients is %hu/%hu && no_empty\n",
						  sv->nbclients, sv->maxclients);
			if (sv->nbclients == sv->maxclients && no_full)
				MsgPrint (MSG_DEBUG,
						  "Reject: nbclients is %hu/%hu && no_full\n",
						  sv->nbclients, sv->maxclients);
		}

		// Check protocol, options
		if (sv->protocol != protocol ||
			(sv->nbclients == 0 && no_empty) ||
			(sv->nbclients == sv->maxclients && no_full))
		{

			// Skip it
			continue;
		}

		// Use the address mapping associated with the server, if any
		if (sv->addrmap != NULL)
		{
			const addrmap_t* addrmap = sv->addrmap;

			sv_addr = ntohl (addrmap->to.sin_addr.s_addr);
			if (addrmap->to.sin_port != 0)
				sv_port = ntohs (addrmap->to.sin_port);

			MsgPrint (MSG_DEBUG,
					  "Server address mapped to %u.%u.%u.%u:%hu\n",
					  sv_addr >> 24, (sv_addr >> 16) & 0xFF,
					  (sv_addr >>  8) & 0xFF, sv_addr & 0xFF,
					  sv_port);
		}

		// IP address
		packet[packetind	] =  sv_addr >> 24;
		packet[packetind + 1] = (sv_addr >> 16) & 0xFF;
		packet[packetind + 2] = (sv_addr >>  8) & 0xFF;
		packet[packetind + 3] =  sv_addr		& 0xFF;

		// Port
		packet[packetind + 4] = sv_port & 0xFF;
		packet[packetind + 5] = sv_port >> 8;

		MsgPrint (MSG_DEBUG, "  - Sending server %u.%u.%u.%u:%hu\n",
				  (qbyte)packet[packetind	], (qbyte)packet[packetind + 1],
				  (qbyte)packet[packetind + 2], (qbyte)packet[packetind + 3],
				  sv_port);

		packetind += 6;
		numServers++;
	}
}

/*
====================
RandomGUID <---- Make it on the master???

Build a guid for an "authKey" message
====================
*/
static void BuildGUID (char *guid)
{
	size_t ind;

	for (ind = 0; ind < GUID_LENGTH; ind++)
	{
		char c;
		do
		{
			c = 33 + rand () % (126 - 33 + 1);  // -> c = 33..126
		} while (c == '\\' || c == ';' || c == '"' || c == '%' || c == '/');

		guid[ind] = c;
	}

	guid[11] = '\0';
}

/*
====================
PrintPacket

Print the contents of a packet on stdout
====================
*/
static void PrintPacket (const char* packet, size_t length)
{
	size_t i;

	// Exceptionally, we use MSG_NOPRINT here because if the function is
	// called, the user probably wants this text to be displayed
	// whatever the maximum message level is.
	MsgPrint (MSG_NOPRINT, "\"");

	for (i = 0; i < length; i++)
	{
		char c = packet[i];
		if (c == '\\')
			MsgPrint (MSG_NOPRINT, "\\\\");
		else if (c == '\"')
			MsgPrint (MSG_NOPRINT, "\"");
		else if (c >= 32 && (qbyte)c <= 127)
		 	MsgPrint (MSG_NOPRINT, "%c", c);
		else
			MsgPrint (MSG_NOPRINT, "\\x%02X", (unsigned char)c);
	}

	MsgPrint (MSG_NOPRINT, "\" (%u bytes)\n", length);
}

/*
====================
HandleclAuth

Parse clAuth requests and send the appropriate response (Always auth)
====================
*/
static void HandleclAuth (const char* msg, const struct sockaddr_in* addr)
{
	char packet [MAX_PACKET_SIZE] = "\xFF\xFF" M2C_AUTHKEY;
	char guid[GUID_LENGTH];

	packet[strlen (packet) + 1] = 1;
	BuildGUID(guid);
	memcpy(packet + strlen (packet) + 2, guid, GUID_LENGTH);

	PrintPacket (packet, M2C_AUTHKEY_LEN_OK);
	sendto (outSock, packet, M2C_AUTHKEY_LEN_OK, 0,
			(const struct sockaddr*)addr,
					sizeof (*addr));

	MsgPrint (MSG_DEBUG, "%s <--- authKey with guid \"%s\"\n",
			  peer_address, guid);
}

/*
====================
HandlegameAuth

Parse clAuth requests and send the appropriate response (Always auth)
====================
*/
static void HandlegameAuth (const char* msg, const struct sockaddr_in* addr)
{
	char packet [MAX_PACKET_SIZE] = "\xFF\xFF" M2C_AUTHKEY;
	char guid[GUID_LENGTH];

	packet[strlen (packet) + 1] = 1;
	BuildGUID(guid);
	memcpy(packet + strlen (packet) + 2, guid, GUID_LENGTH);

	PrintPacket (packet, M2C_AUTHKEY_LEN_OK);
	sendto (outSock, packet, M2C_AUTHKEY_LEN_OK, 0,
			(const struct sockaddr*)addr,
					sizeof (*addr));

	MsgPrint (MSG_DEBUG, "%s <--- authKey with guid \"%s\"\n",
			  peer_address, guid);
}



/*
====================
HandleInfoResponse

Parse infoResponse messages
====================
*/
static void HandleInfoResponse (server_t* server, const char* msg)
{
	char* value;
	unsigned int new_protocol = 0, new_maxclients = 0;

	MsgPrint (MSG_DEBUG, "%s ---> infoResponse\n", peer_address);

	// Check the challenge
	if (!server->challenge_timeout || server->challenge_timeout < crt_time)
	{
		MsgPrint (MSG_WARNING,
				  "WARNING: infoResponse with obsolete challenge from %s\n",
				  peer_address);
		return;
	}
	if(memcmp(&(server->challenge), msg, sizeof(server->challenge)) != 0)
	{
		MsgPrint (MSG_ERROR, "ERROR: invalid challenge from %s (0x%x)\n",
				  peer_address, server->challenge);
		return;
	}
	msg+=sizeof(server->challenge);

	// Check and save the values of "protocol" and "maxclients"
	memcpy(&new_protocol, msg, sizeof(new_protocol));
	msg+=sizeof(new_protocol);

	// some people enjoy making it hard to find them
	value = SearchInfostring (msg, "si_serverURL");
	if (!value || !value[0])
	{
		MsgPrint (MSG_ERROR, "ERROR: no hostname from %s\n",
				  peer_address, value);
		return;
	}

	value = SearchInfostring (msg, "si_maxPlayers");
	if (value)
		new_maxclients = atoi (value);
	if (!new_protocol || !new_maxclients)
	{
		MsgPrint (MSG_ERROR,
				  "ERROR: invalid infoResponse from %s (protocol: %d, maxclients: %d)\n",
				  peer_address, new_protocol, new_maxclients);
		return;
	}
	server->protocol = new_protocol;
	server->maxclients = new_maxclients;

	//TODO
	// Save some other useful values
	value = SearchInfostring (msg, "clients");
	if (value)
		server->nbclients = atoi (value);

	// Set a new timeout
	server->timeout = crt_time + TIMEOUT_INFORESPONSE;
}

// ---------- Public functions ---------- //

/*
====================
HandleMessage

Parse a packet to figure out what to do with it
====================
*/
void HandleMessage (const char* msg, size_t length,
					const struct sockaddr_in* address)
{
	server_t* server;

	// If it's an heartbeat
	if (!strncmp (S2M_HEARTBEAT, msg, strlen (S2M_HEARTBEAT)))
	{
		// Extract the game id
		MsgPrint (MSG_DEBUG, "%s ---> heartbeat\n",
				  peer_address);

		// Get the server in the list (add it to the list if necessary)
		server = Sv_GetByAddr (address, qtrue);
		if (server == NULL)
			return;

		server->active = qtrue;

		// If we haven't yet received any infoResponse from this server,
		// we let it some more time to contact us. After that, only
		// infoResponse messages can update the timeout value.
		if (!server->maxclients)
			server->timeout = crt_time + TIMEOUT_HEARTBEAT;

		// Ask for some infos
		SendGetInfo (server);
	}

	// If it's an infoResponse message
	else if (!strncmp (S2M_INFORESPONSE, msg, strlen (S2M_INFORESPONSE)))
	{
		server = Sv_GetByAddr (address, qfalse);
		if (server == NULL)
			return;

		HandleInfoResponse (server, msg + strlen (S2M_INFORESPONSE) + 1);
	}

	// If it's a getservers request
	else if (!strncmp (C2M_GETSERVERS, msg, strlen (C2M_GETSERVERS)))
	{
		HandleGetServers (msg + strlen (C2M_GETSERVERS) + 1, address);
	}

	// If it's a client auth request
	else if (!strncmp (C2M_CLAUTH, msg, strlen (C2M_CLAUTH)))
	{
		HandleclAuth (msg + strlen (C2M_CLAUTH) + 1, address);
	}

	// If it's a game auth request
	else if (!strncmp (C2M_GAMEAUTH, msg, strlen (C2M_GAMEAUTH)))
	{
		HandlegameAuth (msg + strlen (C2M_GAMEAUTH) + 1, address);
	}
}
