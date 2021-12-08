-- Medius Wireshark Packet Dissector
-- Written by hashsploit <hashsploit@protonmail.com>
-- Ref: https://wiki.hashsploit.net/PlayStation_2#Medius

---------------------------------------------
-- Constants & Enums
---------------------------------------------

local const = {}
const.MESSAGEID_MAXLEN = 21
const.POLICY_MAXLEN = 256
const.NET_MAX_IP_LENGTH = 16 -- This macro defines the length of an IP address string including the null terminator.
const.NET_MAX_ADDRESS_STR_LENGTH = 18 -- This macro defines the maximum length of an IP address (16 bytes) or MAC Address (18 bytes) (including the null terminator).
const.NET_ADDRESS_LIST_COUNT = 2 -- This macro determines the number of addresses in an address list.
const.NET_SESSION_KEY_LEN = 17 -- This macro determines the length of a session key as used in ConnectionInfo (includes NULL terminator).
const.NET_ACCESS_KEY_LEN = 17 -- This macro determines the length of an access key as used in ConnectionInfo (includes NULL terminator).


local MediusConnectionType = {
	[0] = {name="MODEM", desc="The connection is on a modem."},
	[1] = {name="ETHERNET", desc="The connection is on Ethernet."},
	[2] = {name="WIRELESS", desc="The connection is wireless."}
}

local MediusCallbackStatus = {
	[0] = {name="MediusSuccess", desc="Success."},
	[1] = {name="MediusNoResult", desc="No results. This is a valid state."},
	[2] = {name="MediusRequestAccepted", desc="The request has been accepted."},
	[3] = {name="MediusWorldCreatedSizeReduced", desc="The world has been created with reduced size."},
	[4] = {name="MediusPass", desc="The criteria has been met."},
	[-935] = {name="MediusNotAMember", desc="The user is not a member of an list."},
	[-936] = {name="MediusSubscriptionInvalid", desc="The subscription is invalid."},
	[-937] = {name="MediusSubscriptionAborted", desc="The subscription has been aborted."},
	[-938] = {name="MediusTokenDoesNotExist", desc="The token being referenced does not exist."},
	[-939] = {name="MediusTokenAlreadyTaken", desc="The token is already in use."},
	[-940] = {name="MediusSessionFail", desc="The session has failed."},
	[-941] = {name="MediusTransactionCanceled", desc="The transaction has been cancelled."},
	[-942] = {name="MediusGatewayError", desc="There is an internal gateway error."}
	-- TODO: add more
}

local ApplicationId = {
	[10411] = {
		name="Syphon Filter: The Omega Strain",
		desc="NTSC-U, May 4 2004, Medius 1.08",
		date="May 4, 2004",
		medius_version="1.08",
		region="NTSC-U"
	},
	[10683] = {
		name="Ratchet and Clank 3",
		desc="PAL, November 3 2004, Medius 1.08",
		date="November 3, 2004",
		medius_version="1.08",
		region="PAL"
	},
	[10684] = {
		name="Ratchet and Clank: Up Your Arsenal",
		desc="NTSC-U, November 3 2004, Medius 1.08",
		date="November 3, 2004",
		medius_version="1.08",
		region="NTSC-U"
	},
	[10782] = {
		name="Gran Turismo 4 (Beta)",
		desc="NTSC-U, December 28 2004, Medius 1.10",
		date="December 28, 2004",
		medius_version="1.10",
		region="NTSC-U"
	},
	[10994] = {
		name="Jak X: Combat Racing",
		desc="NTSC-U, October 18 2005, Medius 1.09",
		date="October 18, 2005",
		medius_version="1.09",
		region="NTSC-U"
	},
	[11184] = {
		name="Ratchet: Deadlocked",
		desc="NTSC-U, October 25 2005, Medius 1.10",
		date="October 25, 2005",
		medius_version="1.10",
		region="NTSC-U"
	},
	[11204] = {
		name="Jak X: Combat Racing",
		desc="PAL, November 4 2005, Medius 1.09",
		date="November 4, 2005",
		medius_version="1.09",
		region="PAL"
	}
	-- TODO: add more
}

---------------------------------------------
-- RTime ID's
---------------------------------------------

local rtids = {
	[0x00] = {
		name = "RT_MSG_CLIENT_CONNECT_TCP",
		desc = "Normal client connect request, contains Medius version and Game ID.",
		struct_108 = { -- Structure for Medius 1.08 (0x6c) titles
			{
				type = "bytes",
				id = "padding",
				name = "Unknown (Padding?)",
				length = 3,
				display = base.SPACE
			},
			{
				type = "uint8",
				id = "world_id",
				name = "World Id",
				length = 2,
				display = base.DEC_HEX
			},
			{
				type = "uint8",
				id = "app_id",
				name = "App Id",
				length = 4,
				display = base.DEC_HEX,
				enum = ApplicationId
			},
			{
				type = "bytes",
				id = "rsa_key",
				name = "RSA Key",
				length = 64,
				display = base.SPACE
			},
			{
				type = "bytes",
				id = "session_key",
				name = "Session Key",
				length = 17,
				display = base.SPACE,
				optional = true
			},
			{
				type = "bytes",
				id = "access_key",
				name = "Access Key",
				length = 17,
				display = base.SPACE,
				optional = true
			}
		},
		struct_110 = { -- Structure for Medius 1.10 "2.10" (0x6e) titles
			{
				type = "uint8",
				id = "world_id",
				name = "World Id",
				length = 4,
				display = base.DEC_HEX
			},
			{
				type = "uint8",
				id = "app_id",
				name = "App Id",
				length = 4,
				display = base.DEC_HEX,
				enum = ApplicationId
			},
			{
				type = "bytes",
				id = "rsa_key",
				name = "RSA Key",
				length = 64,
				display = base.SPACE
			},
			{
				type = "bytes",
				id = "session_key",
				name = "Session Key",
				length = 17,
				display = base.SPACE,
				optional = true
			},
			{
				type = "bytes",
				id = "access_key",
				name = "Access Key",
				length = 17,
				display = base.SPACE,
				optional = true
			}
		}
	},
	[0x01] = {name="RT_MSG_CLIENT_DISCONNECT", desc="Normal client disconnect."},
	[0x02] = {name="RT_MSG_CLIENT_APP_BROADCAST", desc=nil},
	[0x03] = {name="RT_MSG_CLIENT_APP_SINGLE", desc=nil},
	[0x04] = {name="RT_MSG_CLIENT_APP_LIST", desc=nil},
	[0x05] = {name="RT_MSG_CLIENT_ECHO", desc=nil},
	[0x06] = {name="RT_MSG_SERVER_CONNECT_REJECT", desc=nil},
	[0x07] = {name="RT_MSG_SERVER_CONNECT_ACCEPT_TCP", desc="Login Client IP Address: The server sends the client their ip address. This might be used for NAT hole-punching down the line."},
	[0x08] = {name="RT_MSG_SERVER_CONNECT_NOTIFY", desc=nil},
	[0x09] = {name="RT_MSG_SERVER_DISCONNECT_NOTIFY", desc=nil},
	[0x0a] = {
		name="RT_MSG_SERVER_APP",
		desc="Generic Medius data message to client from server."
	},
	[0x0b] = {
		name="RT_MSG_CLIENT_APP_TOSERVER",
		desc="Generic Medius data message from client to server."
	},
	[0x0c] = {name="RT_MSG_UDP_APP", desc=nil},
	[0x0d] = {name="RT_MSG_CLIENT_SET_RECV_FLAG", desc=nil},
	[0x0e] = {name="RT_MSG_CLIENT_SET_AGG_TIME", desc=nil},
	[0x0f] = {name="RT_MSG_CLIENT_FLUSH_ALL", desc=nil},
	[0x10] = {name="RT_MSG_CLIENT_FLUSH_SINGLE", desc=nil},
	[0x11] = {name="RT_MSG_SERVER_FORCED_DISCONNECT", desc=nil},
	[0x12] = {name="RT_MSG_CLIENT_CRYPTKEY_PUBLIC", desc="The client is requesting to start encryption. The contents is an RSA key generated by the PS2, which is encrypted using public-key of the server (512-bit Textbook RSA). The public-key is burned in the games iso."},
	[0x13] = {name="RT_MSG_SERVER_CRYPTKEY_PEER", desc="The server is accepting encryption. The contents is a custom RC4 or RCQ 'session key' used to encrypt/decrypt messages going forward, this message is encrypted via the RSA key in the client."},
	[0x14] = {name="RT_MSG_SERVER_CRYPTKEY_GAME", desc="Game encryption key."},
	[0x15] = {name="RT_MSG_CLIENT_CONNECT_TCP_AUX_UDP", desc=nil},
	[0x16] = {name="RT_MSG_CLIENT_CONNECT_AUX_UDP", desc=nil},
	[0x17] = {name="RT_MSG_CLIENT_CONNECT_READY_AUX_UDP", desc=nil},
	[0x18] = {name="RT_MSG_SERVER_INFO_AUX_UDP", desc=nil},
	[0x19] = {name="RT_MSG_SERVER_CONNECT_ACCEPT_AUX_UDP", desc=nil},
	[0x1a] = {name="RT_MSG_SERVER_CONNECT_COMPLETE", desc="Connection successful."},
	[0x1b] = {name="RT_MSG_CLIENT_CRYPTKEY_PEER", desc=nil},
	[0x1c] = {name="RT_MSG_SERVER_SYSTEM_MESSAGE", desc=nil},
	[0x1d] = {name="RT_MSG_SERVER_CHEAT_QUERY", desc=nil},
	[0x1e] = {name="RT_MSG_SERVER_MEMORY_POKE", desc=nil},
	[0x1f] = {name="RT_MSG_SERVER_ECHO", desc=nil},
	[0x20] = {name="RT_MSG_CLIENT_DISCONNECT_WITH_REASON", desc=nil},
	[0x21] = {name="RT_MSG_CLIENT_CONNECT_READY_TCP", desc=nil},
	[0x22] = {name="RT_MSG_SERVER_CONNECT_REQUIRE", desc=nil},
	[0x23] = {name="RT_MSG_CLIENT_CONNECT_READY_REQUIRE", desc=nil},
	[0x24] = {name="RT_MSG_CLIENT_HELLO", desc=nil},
	[0x25] = {name="RT_MSG_SERVER_HELLO", desc=nil},
	[0x26] = {name="RT_MSG_SERVER_STARTUP_INFO_NOTIFY", desc=nil},
	[0x27] = {name="RT_MSG_CLIENT_PEER_QUERY", desc=nil},
	[0x28] = {name="RT_MSG_SERVER_PEER_QUERY_NOTIFY", desc=nil},
	[0x29] = {name="RT_MSG_CLIENT_PEER_QUERY_LIST", desc=nil},
	[0x2a] = {name="RT_MSG_SERVER_PEER_QUERY_LIST_NOTIFY", desc=nil},
	[0x2b] = {name="RT_MSG_CLIENT_WALLCLOCK_QUERY", desc=nil},
	[0x2c] = {name="RT_MSG_CLIENT_WALLCLOCK_QUERY_NOTIFY", desc=nil},
	[0x2d] = {name="RT_MSG_CLIENT_TIMEBASE_QUERY", desc=nil},
	[0x2e] = {name="RT_MSG_SERVER_TIMEBASE_QUERY_NOTIFY", desc=nil},
	[0x2f] = {name="RT_MSG_CLIENT_TOKEN_MESSAGE", desc=nil},
	[0x30] = {name="RT_MSG_SERVER_TOKEN_MESSAGE", desc=nil},
	[0x31] = {name="RT_MSG_CLIENT_SYSTEM_MESSAGE", desc=nil},
	[0x32] = {name="RT_MSG_CLIENT_APP_BROADCAST_QOS", desc=nil},
	[0x33] = {name="RT_MSG_CLIENT_APP_SINGLE_QOS", desc=nil},
	[0x34] = {name="RT_MSG_CLIENT_APP_LIST_QOS", desc=nil},
	[0x35] = {name="RT_MSG_CLIENT_MAX_MSGLEN", desc=nil},
	[0x36] = {name="RT_MSG_SERVER_MAX_MSGLEN", desc=nil},
	
	-- PlayStation 3
	[0x3b] = {name="RT_MSG_CLIENT_MULTI_APP_TO_SERVER", desc="Used to send multiple 0x0a App_To_Server and/or 0x05 client echos."},
	[0x3d] = {name="RT_MSG_CLIENT_APP_TO_PLUGIN", desc="Zipper Interactive Games Only."},
	[0x3e] = {name="RT_MSG_SERVER_PLUGIN_TO_APP", desc="Zipper Interactive Games Only."}
}

---------------------------------------------
-- Medius Types
---------------------------------------------

local mediustypes = {
	[0x1000] = {name="DMEClientConnects"},
	[0x1300] = {name="DMERequestServers"},
	[0x1400] = {name="DMEServerResponse"},
	[0x1600] = {name="DMEUpdateClientStatus"},
	[0x1900] = {name="DMELANFindPacket"},
	[0x1A00] = {name="DMELANFindResultsPacket"},
	[0x2100] = {name="DMELANTextMessage"},
	[0x2200] = {name="DMELANRawMessage"},
	[0x0103] = {name="MediusServerAuthenticationRequest"},
	[0x0203] = {name="MediusServerAuthenticationResponse"},
	[0x0303] = {name="MediusServerSessionBeginRequest"},
	[0x0403] = {name="MediusServerSessionBeginResponse"},
	[0x0503] = {name="MediusServerSessionEndRequest"},
	[0x0603] = {name="MediusServerSessionEndResponse"},
	[0x0703] = {name="MediusServerCreateGameRequest"},
	[0x0803] = {name="MediusServerCreateGameResponse"},
	[0x0903] = {name="MediusServerJoinGameRequest"},
	[0x0A03] = {name="MediusServerJoinGameResponse"},
	[0x0B03] = {name="MediusServerEndGameRequest"},
	[0x0C03] = {name="MediusServerEndGameResponse"},
	[0x0D03] = {name="MediusServerWorldStatusRequest"},
	[0x0E03] = {name="MediusServerWorldStatusResponse"},
	[0x1F03] = {name="MediusServerCreateGameOnMeRequest"},
	[0x1003] = {name="MediusServerCreateGameOnMeResponse"},
	[0x1103] = {name="MediusServerEndGameOnMeRequest"},
	[0x1203] = {name="MediusServerEndGameOnMeResponse"},
	[0x1403] = {name="MediusServerMoveGameWorldOnMeRequest"},
	[0x1503] = {name="MediusServerMoveGameWorldOnMeResponse"},
	[0x1603] = {name="MediusServerSetAttributesRequest"},
	[0x1703] = {name="MediusServerSetAttributesResponse"},
	[0x1803] = {name="MediusServerCreateGameWithAttributesRequest"},
	[0x1903] = {name="MediusServerCreateGameWithAttributesResponse"},
	[0x1A03] = {name="MediusServerConnectGamesRequest"},
	[0x1B03] = {name="MediusServerConnectGamesResponse"},
	[0x1E03] = {name="MediusServerDisconnectPlayerRequest"},
	[0x0001] = {name="WorldReport0"},
	[0x0101] = {name="PlayerReport"},
	[0x0201] = {name="EndGameReport"},
	[0x0301] = {
		name = "SessionBegin",
		struct = {
			{
				type = "bytes",
				id = "message_id",
				name = "Message Id",
				length = const.MESSAGEID_MAXLEN,
				display = base.NONE
			},
			{
				type = "bytes",
				id = "padding",
				name = "Padding",
				length = 3,
				display = base.SPACE
			},
			{
				type = "uint8",
				id = "medius_connection_type",
				name = "Medius Connection Type",
				length = 4,
				display = base.DEC_HEX,
				enum = MediusConnectionType
			}
		}
	},
	[0x0401] = {name="SessionBeginResponse"},
	[0x0501] = {name="SessionEnd"},
	[0x0601] = {name="SessionEndResponse"},
	[0x0701] = {name="AccountLogin"},
	[0x0801] = {name="AccountLoginResponse"},
	[0x0901] = {name="AccountRegistration"},
	[0x0A01] = {name="AccountRegistrationResponse"},
	[0x0B01] = {name="AccountGetProfile"},
	[0x0C01] = {name="AccountGetProfileResponse"},
	[0x0D01] = {name="AccountUpdateProfile"},
	[0x0E01] = {name="AccountUpdateProfileResponse"},
	[0x0F01] = {name="AccountUpdatePassword"},
	[0x1101] = {name="AccountUpdateStats"},
	[0x1201] = {name="AccountUpdateStatsResponse"},
	[0x1301] = {name="AccountDelete"},
	[0x1401] = {name="AccountDeleteResponse"},
	[0x1501] = {name="AccountLogout"},
	[0x1601] = {name="AccountLogoutResponse"},
	[0x1701] = {name="AccountGetId"},
	[0x1801] = {name="AccountGetIdResponse"},
	[0x1901] = {name="AnonymousLogin"},
	[0x1A01] = {name="AnonymousLoginResponse"},
	[0x1B01] = {name="GetMyIP"},
	[0x1C01] = {name="GetMyIPResponse"},
	[0x1D01] = {name="CreateGameRequest0"},
	[0x1E01] = {name="CreateGameResponse"},
	[0x1F01] = {name="CreateGameOnSelf"},
	[0x2001] = {name="CreateGameOnSelfResponse"},
	[0x2101] = {name="CreateChannelRequest0"},
	[0x2201] = {name="CreateChannelResponse"},
	[0x2301] = {name="JoinGameRequest0"},
	[0x2401] = {name="JoinGameResponse"},
	[0x2501] = {name="JoinChannel"},
	[0x2601] = {name="JoinChannelResponse"},
	[0x2701] = {name="JoinChannelFwd"},
	[0x2801] = {name="JoinChannelFwdResponse"},
	[0x2901] = {name="GameList"},
	[0x2A01] = {name="GameListResponse"},
	[0x2B01] = {name="ChannelList"},
	[0x2C01] = {name="ChannelListResponse"},
	[0x2D01] = {name="LobbyWorldPlayerList"},
	[0x2E01] = {name="LobbyWorldPlayerListResponse"},
	[0x2F01] = {name="GameWorldPlayerList"},
	[0x3001] = {name="GameWorldPlayerListResponse"},
	[0x3101] = {name="PlayerInfo"},
	[0x3201] = {name="PlayerInfoResponse"},
	[0x3301] = {name="GameInfo0"},
	[0x3401] = {name="GameInfoResponse0"},
	[0x3501] = {name="ChannelInfo"},
	[0x3601] = {name="ChannelInfoResponse"},
	[0x3701] = {name="FindWorldByName"},
	[0x3801] = {name="FindWorldByNameResponse"},
	[0x3901] = {name="FindPlayer"},
	[0x3A01] = {name="FindPlayerResponse"},
	[0x3B01] = {name="ChatMessage"},
	[0x3C01] = {name="ChatFwdMessage"},
	[0x3D01] = {name="GetBuddyList"},
	[0x3E01] = {name="GetBuddyListResponse"},
	[0x3F01] = {name="AddToBuddyList"},
	[0x4001] = {name="AddToBuddyListResponse"},
	[0x4101] = {name="RemoveFromBuddyList"},
	[0x4201] = {name="RemoveFromBuddyListResponse"},
	[0x4301] = {name="AddToBuddyListConfirmationRequest0"},
	[0x4401] = {name="AddToBuddyListConfirmationResponse"},
	[0x4501] = {name="AddToBuddyListFwdConfirmationRequest0"},
	[0x4601] = {name="AddToBuddyListFwdConfirmationResponse0"},
	[0x4701] = {name="Policy"},
	[0x4801] = {
		name = "PolicyResponse",
		struct = {
			{
				type = "bytes",
				id = "message_id",
				name = "Message Id",
				length = const.MESSAGEID_MAXLEN,
				display = base.NONE
			},
			{
				type = "bytes",
				id = "padding",
				name = "Padding",
				length = 3,
				display = base.SPACE
			},
			{
				type = "uint8",
				id = "status",
				name = "Callback Status",
				length = 4,
				display = base.DEC_HEX,
				enum = MediusCallbackStatus
			},
			{
				type = "string",
				id = "message",
				name = "Policy Message",
				length = const.POLICY_MAXLEN,
				display = base.NONE
			},
			{
				type = "bool",
				id = "endofmsg",
				name = "End of Message",
				length = 4,
				display = base.BOOLEAN
			}
		}
	},
	[0x4901] = {name="UpdateUserState"},
	[0x4A01] = {name="ErrorMessage"},
	[0x4B01] = {name="GetAnnouncements"},
	[0x4C01] = {name="GetAllAnnouncements"},
	[0x4D01] = {name="GetAnnouncementsResponse"},
	[0x4E01] = {name="SetGameListFilter0"},
	[0x4F01] = {name="SetGameListFilterResponse0"},
	[0x5001] = {name="ClearGameListFilter0"},
	[0x5101] = {name="ClearGameListFilterResponse"},
	[0x5201] = {name="GetGameListFilter"},
	[0x5301] = {name="GetGameListFilterResponse0"},
	[0x5401] = {name="CreateClan"},
	[0x5501] = {name="CreateClanResponse"},
	[0x5601] = {name="DisbandClan"},
	[0x5701] = {name="DisbandClanResponse"},
	[0x5801] = {name="GetClanByID"},
	[0x5901] = {name="GetClanByIDResponse"},
	[0x5A01] = {name="GetClanByName"},
	[0x5B01] = {name="GetClanByNameResponse"},
	[0x5C01] = {name="TransferClanLeadership"},
	[0x5D01] = {name="TransferClanLeadershipResponse"},
	[0x5E01] = {name="AddPlayerToClan"},
	[0x5F01] = {name="AddPlayerToClanResponse"},
	[0x6001] = {name="RemovePlayerFromClan"},
	[0x6101] = {name="RemovePlayerFromClanResponse"},
	[0x6201] = {name="InvitePlayerToClan"},
	[0x6301] = {name="InvitePlayerToClanResponse"},
	[0x6401] = {name="CheckMyClanInvitations"},
	[0x6501] = {name="CheckMyClanInvitationsResponse"},
	[0x6601] = {name="RespondToClanInvitation"},
	[0x6701] = {name="RespondToClanInvitationResponse"},
	[0x6801] = {name="RevokeClanInvitation"},
	[0x6901] = {name="RevokeClanInvitationResponse"},
	[0x6A01] = {name="RequestClanTeamChallenge"},
	[0x6B01] = {name="RequestClanTeamChallengeResponse"},
	[0x6C01] = {name="GetMyClanMessages"},
	[0x6D01] = {name="GetMyClanMessagesResponse"},
	[0x6E01] = {name="SendClanMessage"},
	[0x6F01] = {name="SendClanMessageResponse"},
	[0x7001] = {name="ModifyClanMessage"},
	[0x7101] = {name="ModifyClanMessageResponse"},
	[0x7201] = {name="DeleteClanMessage"},
	[0x7301] = {name="DeleteClanMessageResponse"},
	[0x7401] = {name="RespondToClanTeamChallenge"},
	[0x7501] = {name="RespondToClanTeamChallengeResponse"},
	[0x7601] = {name="RevokeClanTeamChallenge"},
	[0x7701] = {name="RevokeClanTeamChallengeResponse"},
	[0x7801] = {name="GetClanTeamChallengeHistory"},
	[0x7901] = {name="GetClanTeamChallengeHistoryResponse"},
	[0x7A01] = {name="GetClanInvitationsSent"},
	[0x7B01] = {name="GetClanInvitationsSentResponse"},
	[0x7C01] = {name="GetMyClans"},
	[0x7D01] = {name="GetMyClansResponse"},
	[0x7E01] = {name="GetAllClanMessages"},
	[0x7F01] = {name="GetAllClanMessagesResponse"},
	[0x8001] = {name="ConfirmClanTeamChallenge"},
	[0x8101] = {name="ConfirmClanTeamChallengeResponse"},
	[0x8201] = {name="GetClanTeamChallenges"},
	[0x8301] = {name="GetClanTeamChallengesResponse"},
	[0x8401] = {name="UpdateClanStats"},
	[0x8501] = {name="UpdateClanStatsResponse"},
	[0x8601] = {name="VersionServer"},
	[0x8701] = {name="VersionServerResponse"},
	[0x8801] = {name="GetWorldSecurityLevel"},
	[0x8901] = {name="GetWorldSecurityLevelResponse"},
	[0x8A01] = {name="BanPlayer"},
	[0x8B01] = {name="BanPlayerResponse"},
	[0x8C01] = {name="GetLocations"},
	[0x8D01] = {name="GetLocationsResponse"},
	[0x8E01] = {name="PickLocation"},
	[0x8F01] = {name="PickLocationResponse"},
	[0x9001] = {name="GetClanMemberList"},
	[0x9101] = {name="GetClanMemberListResponse"},
	[0x9201] = {name="LadderPosition"},
	[0x9301] = {name="LadderPositionResponse"},
	[0x9401] = {name="LadderList"},
	[0x9501] = {name="LadderListResponse"},
	[0x9601] = {name="ChatToggle"},
	[0x9701] = {name="ChatToggleResponse"},
	[0x9801] = {name="TextFilter"},
	[0x9901] = {name="TextFilterResponse"},
	[0x9A01] = {name="ServerReassignGameMediusWorldID"},
	[0x9B01] = {name="GetTotalGames"},
	[0x9C01] = {name="GetTotalGamesResponse"},
	[0x9D01] = {name="GetTotalChannels"},
	[0x9E01] = {name="GetTotalChannelsResponse"},
	[0x9F01] = {name="GetLobbyPlayerNames"},
	[0xA001] = {name="GetLobbyPlayerNamesResponse"},
	[0xA101] = {name="GetTotalUsers"},
	[0xA201] = {name="GetTotalUsersResponse"},
	[0xA301] = {name="SetLocalizationParams"},
	[0xA401] = {name="SetLocalizationParamsResponse"},
	[0xA501] = {name="FileCreate"},
	[0xA601] = {name="FileCreateResponse"},
	[0xA701] = {name="FileUpload"},
	[0xA801] = {name="FileUploadResponse"},
	[0xA901] = {name="FileUploadServerReq"},
	[0xAA01] = {name="FileClose"},
	[0xAB01] = {name="FileCloseResponse"},
	[0xAC01] = {name="FileDownload"},
	[0xAD01] = {name="FileDownloadResponse"},
	[0xAE01] = {name="FileDownloadStream"},
	[0xAF01] = {name="FileDownloadStreamResponse"},
	[0xB001] = {name="FileDelete"},
	[0xB101] = {name="FileDeleteResponse"},
	[0xB201] = {name="FileListFiles"},
	[0xB301] = {name="FileListFilesResponse"},
	[0xB401] = {name="FileUpdateAttributes"},
	[0xB501] = {name="FileUpdateAttributesResponse"},
	[0xB601] = {name="FileGetAttributes"},
	[0xB701] = {name="FileGetAttributesResponse"},
	[0xB801] = {name="FileUpdateMetaData"},
	[0xB901] = {name="FileUpdateMetaDataResponse"},
	[0xBA01] = {name="FileGetMetaData"},
	[0xBB01] = {name="FileGetMetaDataResponse"},
	[0xBC01] = {name="FileSearchByMetaData"},
	[0xBD01] = {name="FileSearchByMetaDataResponse"},
	[0xBE01] = {name="FileCancelOperation"},
	[0xBF01] = {name="FileCancelOperationResponse"},
	[0xC001] = {name="GetIgnoreList"},
	[0xC101] = {name="GetIgnoreListResponse"},
	[0xC201] = {name="AddToIgnoreList"},
	[0xC301] = {name="AddToIgnoreListResponse"},
	[0xC401] = {name="RemoveFromIgnoreList"},
	[0xC501] = {name="RemoveFromIgnoreListResponse"},
	[0xC601] = {name="SetMessageAsRead"},
	[0xC701] = {name="SetMessageAsReadResponse"},
	[0xC801] = {name="GetUniverseInformation"},
	[0xC901] = {name="UniverseNewsResponse"},
	[0xCA01] = {name="UniverseStatusListResponse"},
	[0xCB01] = {name="MachineSignaturePost"},
	[0xCC01] = {name="LadderPositionFast"},
	[0xCD01] = {name="LadderPositionFastResponse"},
	[0xCE01] = {name="UpdateLadderStats"},
	[0xCF01] = {name="UpdateLadderStatsResponse"},
	[0xD001] = {name="GetLadderStats"},
	[0xD101] = {name="GetLadderStatsResponse"},
	[0xD601] = {name="GetBuddyList_ExtraInfo"},
	[0xD701] = {name="GetBuddyList_ExtraInfoResponse"},
	[0xD801] = {name="GetTotalRankings"},
	[0xD901] = {name="GetTotalRankingsResponse"},
	[0xDA01] = {name="GetClanMemberList_ExtraInfo"},
	[0xDB01] = {name="GetClanMemberList_ExtraInfoResponse"},
	[0xDC01] = {name="GetLobbyPlayerNames_ExtraInfo"},
	[0xDD01] = {name="GetLobbyPlayerNames_ExtraInfoResponse"},
	[0xDE01] = {name="BillingLogin"},
	[0xDF01] = {name="BillingLoginResponse"},
	[0xE001] = {name="BillingListRequest"},
	[0xE101] = {name="BillingListResponse"},
	[0xE201] = {name="BillingDetailRequest"},
	[0xE301] = {name="BillingDetailResponse"},
	[0xE401] = {name="PurchaseProductRequest"},
	[0xE501] = {name="PurchaseProductResponse"},
	[0xE601] = {name="BillingInfo"},
	[0xE701] = {name="BillingInfoResponse"},
	[0xE801] = {name="BillingTunnelRequest"},
	[0xE901] = {name="BillingTunnelResponse"},
	[0xEA01] = {name="GameList_ExtraInfo0"},
	[0xEB01] = {name="GameList_ExtraInfoResponse0"},
	[0xEC01] = {name="ChannelList_ExtraInfo0"},
	[0xED01] = {name="ChannelList_ExtraInfoResponse"},
	[0xEE01] = {name="InvitePlayerToClan_ByName"},
	[0xEF01] = {name="LadderList_ExtraInfo0"},
	[0xF001] = {name="LadderList_ExtraInfoResponse"},
	[0xF101] = {name="LadderPosition_ExtraInfo"},
	[0xF201] = {name="LadderPosition_ExtraInfoResponse"},
	[0xF301] = {name="JoinGame"},
	[0xF401] = {name="CreateGame1"},
	[0xF501] = {name="UtilAddLobbyWorld"},
	[0xF601] = {name="UtilAddLobbyWorldResponse"},
	[0xF701] = {name="UtilAddGameWorld"},
	[0xF801] = {name="UtilAddGameWorldResponse"},
	[0xF901] = {name="UtilUpdateLobbyWorld"},
	[0xFA01] = {name="UtilUpdateLobbyWorldResponse"},
	[0xFB01] = {name="UtilUpdateGameWorld"},
	[0xFC01] = {name="UtilUpdateGameWorldResponse"},
	[0x0004] = {name="CreateChannel1"},
	[0x0104] = {name="UtilGetServerVersion"},
	[0x0204] = {name="UtilGetServerVersionResponse"},
	[0x0304] = {name="GetUniverse_ExtraInfo"},
	[0x0404] = {name="UniverseStatusList_ExtraInfoResponse"},
	[0x0504] = {name="AddToBuddyListConfirmation"},
	[0x0604] = {name="AddToBuddyListFwdConfirmation"},
	[0x0704] = {name="AddToBuddyListFwdConfirmationResponse"},
	[0x0804] = {name="GetBuddyInvitations"},
	[0x0904] = {name="GetBuddyInvitationsResponse"},
	[0x0A04] = {name="DnasSignaturePost"},
	[0x0B04] = {name="UpdateLadderStatsWide"},
	[0x0C04] = {name="UpdateLadderStatsWideResponse"},
	[0x0D04] = {name="GetLadderStatsWide"},
	[0x0E04] = {name="GetLadderStatsWideResponse"},
	[0x0F04] = {name="LadderList_ExtraInfo"},
	[0x1004] = {name="UtilEventMsgHandler"},
	[0x1104] = {name="UniverseVariableInformationResponse"},
	[0x1204] = {name="SetLobbyWorldFilter"},
	[0x1304] = {name="SetLobbyWorldFilterResponse"},
	[0x1404] = {name="CreateChannel"},
	[0x1504] = {name="ChannelList_ExtraInfo1"},
	[0x1604] = {name="BinaryMessage"},
	[0x1704] = {name="BinaryFwdMessage"},
	[0x1804] = {name="PostDebugInfo"},
	[0x1904] = {name="PostDebugInfoResponse"},
	[0x1A04] = {name="UpdateClanLadderStatsWide_Delta"},
	[0x1B04] = {name="UpdateClanLadderStatsWide_DeltaResponse"},
	[0x1C04] = {name="GetLadderStatsWide_wIDArray"},
	[0x1D04] = {name="GetLadderStatsWide_wIDArray_Response"},
	[0x1E04] = {name="UniverseVariableSvoURLResponse"},
	[0x1F04] = {name="ChannelList_ExtraInfo"},
	[0x2304] = {name="GenericChatMessage"},
	[0x2404] = {name="GenericChatFwdMessage"},
	[0x2504] = {name="GenericChatSetFilterRequest"},
	[0x2604] = {name="GenericChatSetFilterResponse"},
	[0x2704] = {name="ExtendedSessionBeginRequest"},
	[0x2804] = {name="TokenRequest"},
	[0x2C04] = {name="VoteToBanPlayerRequest"},
	[0x2A04] = {name="GetServerTimeRequest"},
	[0x2B04] = {name="GetServerTimeResponse"},
	[0x2D04] = {name="SetAutoChatHistoryRequest"},
	[0x2E04] = {name="SetAutoChatHistoryResponse"},
	[0x2F04] = {name="CreateGame"},
	[0x3304] = {name="SetGameListFilter"},
	[0x3104] = {name="ClearGameListFilter"},
	[0x3004] = {name="WorldReport"},
	[0x3504] = {name="GameInfo"},
	[0x3604] = {name="GameInfoResponse"},
	[0x3704] = {name="GameList_ExtraInfo"},
	[0x3804] = {name="GameList_ExtraInfoResponse"},
	[0x3904] = {name="AccountUpdateStats_OpenAccess"},
	[0x3A04] = {name="AccountUpdateStats_OpenAccessResponse"},
	[0x3B04] = {name="AddPlayerToClan_ByClanOfficer"},
	[0x3C04] = {name="AddPlayerToClan_ByClanOfficerResponse"},
	[0x0054] = {name="UnkRequestKz2"},
	[0x0055] = {name="UnkResponseKz2"},
	[0x0056] = {name="PlayerInfo1"},
	[0x0058] = {name="TicketLogin"},
	[0x0059] = {name="TicketLoginResponse"},
	[0x005A] = {name="SetLocalizationParams2"},
	[0x005B] = {name="SetLocalizationParams2Response"},
	[0x007B] = {name="SetLocalizationParams1"},
	[0x008B] = {name="SessionBegin1"},
	[0x0086] = {name="SetLobbyWorldFilter1"},
	[0x0087] = {name="SetLobbyWorldFilterResponse1"},
	[0x0075] = {name="CreateClan2"}
}

---------------------------------------------
-- Core
---------------------------------------------

local plugin_info = {
	version = "1.3.0",
	author = "hashsploit",
	repository = "https://github.com/hashsploit/medius-wireshark"
}

function string:split(delimiter)
	local result = {}
	local from  = 1
	local delim_from, delim_to = string.find(self, delimiter, from)
	
	while delim_from do
		table.insert( result, string.sub(self, from, delim_from-1))
		from = delim_to + 1
		delim_from, delim_to = string.find(self, delimiter, from)
	end
	
	table.insert(result, string.sub(self, from))
	return result
end

local function get_current_path()
	local delimiter = package.path:sub(1, 1)
	
	-- Windows fix
	if delimiter ~= "/" then
		delimiter = "\\"
	end
	
	local split_path = string.split(string.sub(debug.getinfo(1).source, 2), delimiter)
	local path = ""
	
	for k, v in pairs(split_path) do
		if k > 1 and k < #split_path then
			path = path .. delimiter .. v
		end
	end
	
	-- Windows fix
	if delimiter ~= "/" then
		path = split_path[1] .. path
	end
	
	return path .. delimiter
end

local agreement_path = get_current_path() .. "agree.tmp"

set_plugin_info(plugin_info)

function log(msg)
	print("[Medius Wireshark Dissector] " .. tostring(msg))
end

function file_exists(name)
	local f = io.open(name, "r")
	if f~=nil then io.close(f) return true else return false end
end

log("Version " .. plugin_info["version"])
log("Initializing (stage 1) ...")

local medius_protocol = Proto("medius",  "Medius Protocol")
medius_protocol.fields = {}

local medius_protocol_msg = {}
medius_protocol_msg["type"] = ProtoField.string("medius.type", "Message Type", base.NONE)
medius_protocol_msg["length"] = ProtoField.uint8("medius.length", "Message Length", base.DEC_HEX)
medius_protocol_msg["encrypted"] = ProtoField.string("medius.encrypted", "Message Encrypted", base.NONE)
medius_protocol_msg["chksum"] = ProtoField.uint16("medius.chksum", "Message Checksum", base.HEX)
medius_protocol_msg["data"] = ProtoField.bytes("medius.data", "Message Data", base.SPACE)
medius_protocol_msg["app"] = ProtoField.protocol("medius.app", "Application Data", base.NONE)

local medius_app_protocol = {}
medius_app_protocol["type"] = ProtoField.string("medius.app.type", "App Message Type", base.NONE)

for i, _ in pairs(medius_protocol_msg) do
	table.insert(medius_protocol.fields, medius_protocol_msg[i])
end

for i, _ in pairs(medius_app_protocol) do
	table.insert(medius_protocol.fields, medius_app_protocol[i])
end

-- Add RT Types
for i, _ in pairs(rtids) do
	
	for j, _ in pairs(rtids[i]) do
		
		if j ~= nil and j:match("struct_") then
			
			for k, _ in pairs(rtids[i][j]) do
				local object = rtids[i][j][k]
				local d_type = object.type
				local d_id = object.id
				local d_name = object.name
				local d_length = object.length
				local d_display = object.display or base.NONE
				local d_enum = object.enum
				local d_optional = object.optional
				
				if rtids[i].fields == nil then
					rtids[i].fields = {}
				end
				
				if d_enum ~= nil then
					d_type = "string"
					d_display = base.NONE
				end
				
				local fulldomain = "medius.pkt." .. rtids[i].name .. "." .. j .."." .. d_id
				
				rtids[i].fields[j .. "." .. d_id] = ProtoField[d_type](fulldomain, d_name, d_display)
				table.insert(medius_protocol.fields, rtids[i].fields[j.."."..d_id])
				
			end
			
			
		end
	end
end

-- Add Medius Types
for i, _ in pairs(mediustypes) do
	if mediustypes[i].struct ~= nil then
		for j, _ in ipairs(mediustypes[i].struct) do
			local object = mediustypes[i].struct[j]
			local d_type = object.type
			local d_id = object.id
			local d_name = object.name
			local d_length = object.length
			local d_display = object.display or base.NONE
			local d_enum = object.enum
			
			if mediustypes[i].fields == nil then
				mediustypes[i].fields = {}
			end
			
			if d_enum ~= nil then
				d_type = "string"
				d_display = base.NONE
			end
			
			local fulldomain = "medius.app.pkt." .. mediustypes[i].name .."." .. d_id
			
			mediustypes[i].fields[d_id] = ProtoField[d_type](fulldomain, d_name, d_display)
			table.insert(medius_protocol.fields, mediustypes[i].fields[d_id])
		end
	end
end

local function init()
	log("Initializing (stage 2) ...")
	
	---------------------------------------------
	-- Dissector
	---------------------------------------------

	medius_protocol.dissector = function(buffer, pinfo, tree)
		local length = buffer:len()
		local medius_protocol_msg = medius_protocol_msg
		
		if length < 3 then
			return
		end

		local subtree = tree:add(medius_protocol, buffer(), "Medius Protocol Data")
		
		local rtid          = buffer(0, 1):uint()
		local adjusted_rtid = rtid
		local encrypted     = false
		
		-- Check if the packet is encrypted
		if rtid >= 0x80 then
			encrypted = true
			adjusted_rtid = rtid - 0x80
		end
		
		local offset        = 0
		local rt_length     = buffer(1, 2):le_uint()
		local hash_offset   = (encrypted and 4 or 0)
		
		if rt_length > (length - (1 + 2 + hash_offset)) then
			return
		end
		
		if encrypted then
			adjusted_rtid = rtid - 0x80
		end
		
		local rt_name = "UNKNOWN"
		
		if rtids[adjusted_rtid] ~= nil then
			rt_name = rtids[adjusted_rtid].name
		end
		
		-- This packet is potentially a fragment?
		if rt_length ~= (length - (1 + 2 + hash_offset)) and not encrypted then
			rt_name = rt_name .. "*"
		end
		
		-- Set column info
		pinfo.cols.protocol = medius_protocol.name
		pinfo.cols.info = pinfo.src_port .. " → " .. pinfo.dst_port .. " [" .. rt_name .. "] "
		
		-- Set RT dissection info
		subtree:add_le(medius_protocol_msg["type"], buffer(offset, 1), rt_name .. " (" .. string.format("0x%02x", adjusted_rtid) .. ")")
		offset = offset + 1
		
		subtree:add_le(medius_protocol_msg["length"], buffer(offset, 2))
		offset = offset + 2
		
		subtree:add(medius_protocol_msg["encrypted"], (encrypted and "true" or "false") .. " (" .. string.format("0x%02x", rtid) .. (encrypted and " >= " or " < ") .. "0x80)")
		
		-- TODO: parse multiple message frames in a single packet
		
		-- If the message is encrypted ...
		if encrypted then
			subtree:add_le(medius_protocol_msg["chksum"], buffer(offset, 4))
			offset = offset + 4
			
			-- Show raw encrypted data
			subtree:add_le(medius_protocol_msg["data"], buffer(offset, length - offset))
		else
			
			--[[
			for i, _ in pairs(rtids[rtid]) do
				if i:match("struct_") ~= nil then
					local struct_name = i
					local medius_version_number = tonumber(i:split("struct_")[2])
					local medius_version = tostring((medius_version_number * 1.00) / 100)
					local total_struct_length = 0
					
					for j, _ in pairs(rtids[rtid][struct_name]) do
						local struct = rtids[rtid][struct_name][j]
						
						if struct.optional ~= nil and struct.optional == true then
							if total_struct_length == (length - offset) then
								
								local d_type = struct.type
								local d_id = struct.id
								local d_name = struct.name
								local d_length = struct.length
								local d_display = struct.display or base.NONE
								local d_enum = struct.enum
								local field = rtids[rtid].fields[struct_name.."."..d_id]
								local displaytext = nil
								
								if d_enum ~= nil then
									for k, _ in pairs(d_enum) do
										if k == buffer(offset, d_length):le_uint() then
											local hexlen = tostring(d_length)
											if d_length <= 9 then
												hexlen = "0" .. tostring(d_length)
											end
											if d_length <= 99 then
												hexlen = "00" .. tostring(d_length)
											end
											if d_length <= 999 then
												hexlen = "000" .. tostring(d_length)
											end
											displaytext = d_enum[k].name .. " (" .. k .. ") (" .. string.format("0x%" .. hexlen .. "x", k) .. ")"
										end
									end
								end
								
								if displaytext ~= nil then
									subtree:add(field, buffer(offset, d_length), displaytext)
								else
									if d_type == "uint8" or d_type == "uint16" or d_type == "uint32" then
										subtree:add_le(field, buffer(offset, d_length))
									else
										subtree:add(field, buffer(offset, d_length))
									end
								end
								
								offset = offset + d_length
								
								break
							end
						end
						
						total_struct_length = total_struct_length + struct.length
						
						if total_struct_length == (length - offset) then
							
							local d_type = struct.type
							local d_id = struct.id
							local d_name = struct.name
							local d_length = struct.length
							local d_display = struct.display or base.NONE
							local d_enum = struct.enum
							local field = rtids[rtid].fields[struct_name.."."..d_id]
							local displaytext = nil
							
							if d_enum ~= nil then
								for k, _ in pairs(d_enum) do
									if k == buffer(offset, d_length):le_uint() then
										local hexlen = tostring(d_length)
										if d_length <= 9 then
											hexlen = "0" .. tostring(d_length)
										end
										if d_length <= 99 then
											hexlen = "00" .. tostring(d_length)
										end
										if d_length <= 999 then
											hexlen = "000" .. tostring(d_length)
										end
										displaytext = d_enum[k].name .. " (" .. k .. ") (" .. string.format("0x%" .. hexlen .. "x", k) .. ")"
									end
								end
							end
							
							if displaytext ~= nil then
								subtree:add(field, buffer(offset, d_length), displaytext)
							else
								if d_type == "uint8" or d_type == "uint16" or d_type == "uint32" then
									subtree:add_le(field, buffer(offset, d_length))
								else
									subtree:add(field, buffer(offset, d_length))
								end
							end
							
							offset = offset + d_length
							
							break
						end
						
					end
					
					
					
				end
			end
			--]]
			
			
			-- Just show raw data
			subtree:add_le(medius_protocol_msg["data"], buffer(offset, length - offset))
			
			if rtids[adjusted_rtid] == nil then
				return
			end
			
			-- If this is an "APP" packet ...
			if string.match(rtids[adjusted_rtid].name, "APP") then
				
				local appmsgtype = buffer(offset, 2):le_uint()
				offset = offset + 2
				
				-- Show application data
				local apptree = subtree:add(medius_protocol_msg["app"], buffer(offset-2), "Application Data")
				
				
				-- FIXME: this doesn't need to be in a loop ... just grab it from mediustypes[appmsgtype]
				for i, _ in pairs(mediustypes) do
					if i == appmsgtype then
						
						-- Update info column string
						pinfo.cols.info:append(mediustypes[i].name .. " ")
						
						apptree:add(medius_app_protocol["type"], buffer(offset-2, 2), mediustypes[i].name .. " (" .. string.format("0x%04x", i) .. ")")
						
						if mediustypes[i].struct ~= nil then
							for j, _ in ipairs(mediustypes[i].struct) do
								local object = mediustypes[i].struct[j]
								local d_type = object.type
								local d_id = object.id
								local d_name = object.name
								local d_length = object.length
								local d_display = object.display or base.NONE
								local d_enum = object.enum
								local field = mediustypes[i].fields[d_id]
								local displaytext = nil
								
								if d_enum ~= nil then
									for k, _ in pairs(d_enum) do
										if k == buffer(offset, d_length):le_uint() then
											local hexlen = tostring(d_length)
											if d_length <= 9 then
												hexlen = "0" .. tostring(d_length)
											end
											if d_length <= 99 then
												hexlen = "00" .. tostring(d_length)
											end
											if d_length <= 999 then
												hexlen = "000" .. tostring(d_length)
											end
											displaytext = d_enum[k].name .. " (" .. k .. ") (" .. string.format("0x%" .. hexlen .. "x", k) .. ")"
										end
									end
								end
								
								if displaytext ~= nil then
									apptree:add(field, buffer(offset, d_length), displaytext)
								else
									if d_type == "uint8" or d_type == "uint16" or d_type == "uint32" then
										apptree:add_le(field, buffer(offset, d_length))
									else
										apptree:add(field, buffer(offset, d_length))
									end
								end
								
								offset = offset + d_length
							end
						end
						
						break
					end
				end
				
				
				
			end
		end
	end
	
	---------------------------------------------
	-- Bindings
	---------------------------------------------

	local tcp_port = DissectorTable.get("tcp.port")
	local udp_port = DissectorTable.get("udp.port")

	tcp_port:add(10071, medius_protocol) -- MUIS
		tcp_port:add(20071, medius_protocol)
		tcp_port:add(30071, medius_protocol)
	
	tcp_port:add(10075, medius_protocol) -- MAS
		tcp_port:add(20075, medius_protocol)
		tcp_port:add(30075, medius_protocol)
	
	tcp_port:add(10078, medius_protocol) -- MLS
		tcp_port:add(20078, medius_protocol)
		tcp_port:add(30078, medius_protocol)
	
	tcp_port:add(10079, medius_protocol) -- DME (TCP)
	
	udp_port:add(50000, medius_protocol) -- DME (UDP)
		udp_port:add(50001, medius_protocol)
		udp_port:add(50002, medius_protocol)
		udp_port:add(50003, medius_protocol)
		udp_port:add(51000, medius_protocol)
	
	--udp_port:add(10070, medius_nat_protocol) -- NAT
	
	-- Required in GUI
	if gui_enabled() then
		reload_packets()
	end
	
	log("Initialized")
	
end

local function show_agreement()
	if not gui_enabled() then
		log("This plugin requires the GUI to work!")
		os.exit(5)
		return
	end
	
	local mwd_usage_agree = false
	
	-- create new text window and initialize its text
	local win = TextWindow.new("Medius Wireshark Dissector Usage Agreement")
	win:set_editable(false)
	win:set("Medius Wireshark Dissector\n")
	win:append(" - Version: " .. plugin_info["version"] .. "\n")
	win:append(" - Author: " .. plugin_info["author"] .. "\n")
	win:append(" - Website: " .. plugin_info["repository"] .. "\n")
	win:append(" - Wireshark Version: " .. get_version() .. "\n")
	win:append(" - Lua Version: " .. _VERSION .. "\n")
	win:append("\n")
	
	win:append("By using this dissector you agree to the following:\n")
	win:append(" - Not be a dick and use this plugin against other Medius servers you do not own or are not authorized to reverse engineer.\n")
	win:append(" - Abide by the license and usage agreement this plugin is distributed under.\n")
	win:append(" - When distributing this plugin/script to keep this usage agreement intact and provide credit to all the original author(s).\n\n")
	win:append("______________________________\n\n")
	win:append("MIT LICENSE\n")
	win:append([[Copyright (c) 2020 hashsploit <hashsploit@protonmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
]])

	win:add_button("Website", function()
		browser_open_url(plugin_info["repository"])
	end)

	win:add_button("Agree", function()
		log("Usage agreement accepted!")
		mwd_usage_agree = true
		
		local file = io.open(agreement_path, "w")
		local current_date = tonumber(os.time(os.date("!*t")))
		local path = get_current_path()
		
		file:write(plugin_info["version"] .. "\n")
		file:write(current_date .. "\n")
		file:write(path .. "\n")
		
		file:close()
		
		win:close()
	end)
	
	win:add_button("Decline", function()
		win:close()
	end)

	-- print "closing" to stdout when the user closes the text windw
	win:set_atclose(function()
		
		if not mwd_usage_agree then
			log("Usage agreement declined!")
			os.exit(12)
			return
		end
		
		init()
	end)
	
end

local function check_agreement()
	
	if not file_exists(agreement_path) then
		show_agreement()
		return
	end
	
	local file = io.open(agreement_path, "r")
	local version = file:read()
	local current_date = tonumber(os.time(os.date("!*t")))
	local agreed_date = file:read()
	local path = file:read()
	file:close()
	
	log("Agreement file version: " .. tostring(version))
	
	if version == nil or agreed_date == nil or path == nil then
		os.remove(agreement_path)
		show_agreement()
		return
	end
	
	if not (tonumber(agreed_date) >= 1) then
		os.remove(agreement_path)
		show_agreement()
		return
	end
	
	if version ~= plugin_info["version"] or current_date > (agreed_date + (30 * (60 * 60 * 24))) or path ~= get_current_path() then
		os.remove(agreement_path)
		show_agreement()
		return
	end
	
	init()
end

check_agreement()

